package org.tunaos.tuta

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.io.encoding.Base64

/** A recipient: a display name (may be empty) and an address. */
data class Recipient(val name: String, val address: String)

/** An attachment to send: [cid] makes it inline (`cid:` in the HTML body). */
class OutgoingAttachment(
    val name: String,
    val mimeType: String,
    val data: ByteArray,
    val cid: String? = null,
) {
    override fun toString(): String = "OutgoingAttachment(name=$name, mimeType=$mimeType, cid=$cid, bytes=${data.size})"
}

/** What a reply-to-or-forward does with its parent (README, "Replies and forwards"). */
enum class ThreadAction(internal val wire: String) {
    REPLY("reply"),
    REPLY_ALL("reply_all"),
    FORWARD("forward"),
}

/**
 * A mail's place in a conversation: the parent's Message-ID ([inReplyTo],
 * with or without angle brackets), the References chain (whitespace
 * separated, oldest first) and the [action]. All null for a new
 * conversation.
 */
data class MailThread(
    val inReplyTo: String? = null,
    val references: String? = null,
    val action: ThreadAction? = null,
)

/**
 * A mail to send (README, "Delivery"). [confidential] asks for end-to-end
 * encryption; recipients outside Tuta then need a [passwords] entry each.
 * An ordinary send to anyone outside Tuta needs [ordinaryConfirmed].
 */
class SendRequest(
    val sender: String,
    val senderName: String,
    val to: List<Recipient> = emptyList(),
    val cc: List<Recipient> = emptyList(),
    val bcc: List<Recipient> = emptyList(),
    val replyTos: List<Recipient> = emptyList(),
    val subject: String,
    val bodyHtml: String,
    val confidential: Boolean,
    val ordinaryConfirmed: Boolean = false,
    /** Passwords for the recipients outside Tuta, by address. */
    val passwords: Map<String, String> = emptyMap(),
    val attachments: List<OutgoingAttachment> = emptyList(),
    val thread: MailThread = MailThread(),
) {
    override fun toString(): String = "SendRequest(subject=<redacted>, recipients=${to.size + cc.size + bcc.size})"

    internal fun JsonObjectBuilder.fields() {
        mail(sender, senderName, to, cc, bcc, replyTos, subject, bodyHtml, confidential, attachments, thread)
        put("ordinary_confirmed", ordinaryConfirmed)
        put("passwords", JsonObject(passwords.mapValues { JsonPrimitive(it.value) }))
    }
}

/**
 * A draft to save: a new one in Drafts, or [draftId]'s replacement. Its
 * [thread] counts only when the draft is created.
 */
class DraftRequest(
    val draftId: String? = null,
    val sender: String,
    val senderName: String,
    val to: List<Recipient> = emptyList(),
    val cc: List<Recipient> = emptyList(),
    val bcc: List<Recipient> = emptyList(),
    val replyTos: List<Recipient> = emptyList(),
    val subject: String,
    val bodyHtml: String,
    val confidential: Boolean,
    val attachments: List<OutgoingAttachment> = emptyList(),
    val thread: MailThread = MailThread(),
) {
    override fun toString(): String = "DraftRequest(draftId=$draftId, subject=<redacted>)"

    internal fun JsonObjectBuilder.fields() {
        draftId?.let { put("draft_id", it) }
        mail(sender, senderName, to, cc, bcc, replyTos, subject, bodyHtml, confidential, attachments, thread)
    }
}

/**
 * What [TutaClient.search] looks for (README, "Search"). Every criterion
 * given must hold, and at least one must be given. Text criteria are
 * case-insensitive substrings of at most 256 characters: [keyword] looks in
 * the subject, the sender, the recipients and the body text, [recipient] in
 * To, Cc and Bcc. [afterMs] (inclusive) and [beforeMs] (exclusive) bound the
 * received date, in milliseconds since the epoch.
 */
data class SearchQuery(
    val keyword: String? = null,
    val subject: String? = null,
    val sender: String? = null,
    val recipient: String? = null,
    val afterMs: Long? = null,
    val beforeMs: Long? = null,
    val isUnread: Boolean? = null,
) {
    override fun toString(): String = "SearchQuery(<redacted>)"

    internal fun JsonObjectBuilder.fields() {
        keyword?.let { put("keyword", it) }
        subject?.let { put("subject", it) }
        sender?.let { put("sender", it) }
        recipient?.let { put("recipient", it) }
        afterMs?.let { put("after_ms", it) }
        beforeMs?.let { put("before_ms", it) }
        isUnread?.let { put("is_unread", it) }
    }
}

private fun JsonObjectBuilder.mail(
    sender: String,
    senderName: String,
    to: List<Recipient>,
    cc: List<Recipient>,
    bcc: List<Recipient>,
    replyTos: List<Recipient>,
    subject: String,
    bodyHtml: String,
    confidential: Boolean,
    attachments: List<OutgoingAttachment>,
    thread: MailThread,
) {
    put("sender", sender)
    put("sender_name", senderName)
    put("to", recipients(to))
    put("cc", recipients(cc))
    put("bcc", recipients(bcc))
    put("reply_tos", recipients(replyTos))
    put("subject", subject)
    put("body_html", bodyHtml)
    put("confidential", confidential)
    put(
        "attachments",
        JsonArray(
            attachments.map {
                buildJsonObject {
                    put("name", it.name)
                    put("mime_type", it.mimeType)
                    put("cid", it.cid)
                    put("data", Base64.encode(it.data))
                }
            },
        ),
    )
    thread.inReplyTo?.let { put("in_reply_to", it) }
    thread.references?.let { put("references", it) }
    thread.action?.let { put("action", it.wire) }
}

private fun recipients(list: List<Recipient>) = JsonArray(
    list.map {
        buildJsonObject {
            put("name", it.name)
            put("address", it.address)
        }
    },
)
