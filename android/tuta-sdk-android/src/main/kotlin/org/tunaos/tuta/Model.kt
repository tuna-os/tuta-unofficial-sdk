package org.tunaos.tuta

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.encoding.Base64

// The protocol's result objects (README, "The helper protocol"), decoded
// leniently: a field or enum value a newer native library adds is ignored or
// falls back, rather than failing the call.
internal val TutaJson = Json {
    ignoreUnknownKeys = true
    coerceInputValues = true
}

/** What a system folder is for; custom folders are [OTHER]. */
@Serializable
enum class FolderRole {
    @SerialName("inbox") INBOX,
    @SerialName("sent") SENT,
    @SerialName("trash") TRASH,
    @SerialName("archive") ARCHIVE,

    /** Spam. */
    @SerialName("junk") JUNK,
    @SerialName("drafts") DRAFTS,
    @SerialName("other") OTHER,
}

/** One folder of the tree. Ids are compound `list/element` ids. */
@Serializable
data class Folder(
    val id: String,
    val role: FolderRole = FolderRole.OTHER,
    /** Its name, or the role's English name for an unnamed system folder. */
    val label: String,
    /** The parent folder's id; null at the top level (`""` on the wire). */
    @Serializable(with = EmptyAsNull::class)
    val parent: String? = null,
)

/** A label: a mail set beside the folders, colour `#rrggbb` (or empty). */
@Serializable
data class Label(val id: String, val name: String, val color: String)

/** A name and an address. */
@Serializable
data class Address(val name: String, val address: String)

/**
 * A mail's header as listed and as read. [messageId] is the mail's own
 * Message-ID, bare, or null for a draft; [replyType] is Tuta's replied or
 * forwarded mark (0 none, 1 replied, 2 forwarded, 3 both).
 */
@Serializable
data class MailHeader(
    val id: String,
    val subject: String,
    @SerialName("date_ms") val dateMs: Long,
    val sender: Address,
    val recipient: Address? = null,
    @SerialName("is_unread") val isUnread: Boolean,
    val confidential: Boolean,
    /** The conversation entry's list id: one per conversation. */
    val conversation: String,
    @SerialName("message_id") val messageId: String? = null,
    @SerialName("has_attachments") val hasAttachments: Boolean,
    @SerialName("reply_type") val replyType: Int = 0,
)

/** A listed mail: its header and the ids of the labels it carries. */
@Serializable(with = ListedMailSerializer::class)
data class ListedMail(val header: MailHeader, val labels: List<String>)

/**
 * One [TutaClient.sync] page: the folder tree, the labels, a page of the
 * selected [folder] newest first, how many mails it holds ([exists]) and,
 * on the first page only, every id it holds ([allIds], authoritative: a
 * cache may prune what it does not list).
 */
@Serializable
data class SyncPage(
    val folders: List<Folder>,
    val labels: List<Label>,
    val messages: List<ListedMail>,
    val folder: String,
    val exists: Long,
    @SerialName("all_ids") val allIds: List<String>? = null,
    val offset: Long,
)

/** A decrypted attachment. */
@Serializable
data class Attachment(
    val name: String,
    @SerialName("mime_type") val mimeType: String? = null,
    val cid: String? = null,
    /** The bytes, standard base64 (see [bytes]). */
    val data: String,
) {
    /** The decoded bytes. */
    fun bytes(): ByteArray = Base64.decode(data)

    override fun toString(): String = "Attachment(name=$name, mimeType=$mimeType, cid=$cid, base64Length=${data.length})"
}

/**
 * A decrypted message: its [header], the HTML body, the original header
 * block (empty for mail between Tuta accounts), recipients and attachments.
 */
@Serializable
data class Message(
    val header: MailHeader,
    val html: String,
    val headers: String,
    val to: List<Address>,
    val cc: List<Address>,
    @SerialName("reply_to") val replyTo: List<Address>,
    val attachments: List<Attachment>,
)

/**
 * What became of one id of a batch: [code] is null when applied,
 * `not_attempted` when an earlier batch failed, else the failure's code.
 */
@Serializable
data class IdOutcome(val id: String, val code: String? = null) {
    val isApplied: Boolean get() = code == null
    val isAttempted: Boolean get() = code != NOT_ATTEMPTED

    /** The failure, if this id's batch failed. */
    val error: TutaException? get() = code?.takeIf { it != NOT_ATTEMPTED }?.let(TutaException::of)
}

/**
 * A moved id's outcome: [newId] (a Tuta mail keeps its id) and [source], the
 * folder it left -- what to move it back to for an undo. Both null when the
 * server did not move it (it was already there).
 */
@Serializable
data class MoveOutcome(
    val id: String,
    val code: String? = null,
    @SerialName("new_id") val newId: String? = null,
    val source: String? = null,
) {
    val isApplied: Boolean get() = code == null
    val error: TutaException? get() = code?.takeIf { it != NOT_ATTEMPTED }?.let(TutaException::of)
}

internal const val NOT_ATTEMPTED = "not_attempted"

/** What [TutaClient.deleteFolder] did. */
@Serializable
enum class FolderDeletion {
    /** Deleted for good, with its mail. */
    @SerialName("deleted") DELETED,

    /** Moved under Trash with its mail. */
    @SerialName("trashed") TRASHED,
}

/** The key-exchange protocol of a Tuta recipient's key. */
@Serializable
enum class KeyProtocol {
    @SerialName("tuta_crypt") TUTA_CRYPT,
    @SerialName("rsa") RSA,
}

/**
 * A Tuta recipient's key as a confidential send used it: never key bytes,
 * its version and the hex SHA-256 [fingerprint] for pinning.
 */
@Serializable
data class RecipientReport(
    val address: String,
    @SerialName("key_version") val keyVersion: Long,
    val protocol: KeyProtocol,
    val fingerprint: String,
)

/**
 * A sent mail (README, "Delivery" and "Send outcomes"). The ids are null
 * when the server accepted the send but its reply was lost; the delivery
 * fields are null when the run overran after the submit.
 */
@Serializable
data class SendOutcome(
    @SerialName("message_id") val messageId: String? = null,
    @SerialName("sent_date_ms") val sentDateMs: Long? = null,
    @SerialName("sent_mail") val sentMail: String? = null,
    @SerialName("internal_recipients") val internalRecipients: Int? = null,
    @SerialName("external_recipients") val externalRecipients: Int? = null,
    /** Whether it went out end-to-end encrypted. */
    val confidential: Boolean? = null,
    val recipients: List<RecipientReport>? = null,
    /** The recipients outside Tuta that got it password-protected. */
    @SerialName("secure_external") val secureExternal: List<String>? = null,
    @SerialName("contacts_saved") val contactsSaved: Boolean? = null,
    /** For a reply or forward: whether the parent ended up marked. */
    @SerialName("parent_marked") val parentMarked: Boolean? = null,
)

/**
 * A recipient's contact password: [external] is true outside Tuta, false on
 * Tuta, null when the lookup failed; [password] is the one its contact keeps.
 */
@Serializable
data class ContactPassword(
    val address: String,
    val external: Boolean? = null,
    val password: String? = null,
) {
    override fun toString(): String =
        "ContactPassword(address=$address, external=$external, password=${if (password == null) "null" else "<redacted>"})"
}

/** `""` on the wire for "none". */
internal object EmptyAsNull : KSerializer<String?> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("org.tunaos.tuta.EmptyAsNull", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): String? = decoder.decodeString().ifEmpty { null }

    override fun serialize(encoder: Encoder, value: String?) = encoder.encodeString(value.orEmpty())
}

/** A listed mail is its header's fields plus `labels`, flattened. */
internal object ListedMailSerializer : KSerializer<ListedMail> {
    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor

    override fun deserialize(decoder: Decoder): ListedMail {
        val json = (decoder as JsonDecoder).json
        val fields = decoder.decodeJsonElement() as JsonObject
        val labels = fields["labels"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty()
        return ListedMail(json.decodeFromJsonElement(MailHeader.serializer(), fields), labels)
    }

    override fun serialize(encoder: Encoder, value: ListedMail) {
        val json = (encoder as JsonEncoder).json
        val header = json.encodeToJsonElement(MailHeader.serializer(), value.header) as JsonObject
        encoder.encodeJsonElement(
            buildJsonObject {
                header.forEach { (key, element) -> put(key, element) }
                put("labels", JsonArray(value.labels.map(::JsonPrimitive)))
            },
        )
    }
}
