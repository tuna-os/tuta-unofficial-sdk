package org.tunaos.tuta

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import org.tunaos.tuta.ffi.NativeException
import org.tunaos.tuta.ffi.TutaFfi
import org.tunaos.tuta.ffi.WatchListener
import kotlin.io.encoding.Base64
import org.tunaos.tuta.ffi.errorCodes as ffiErrorCodes
import org.tunaos.tuta.ffi.protocolVersion as ffiProtocolVersion

/**
 * Tuta, in process: each call is one request of the `tuta-helper` protocol
 * (the repository README, "The helper protocol"), run by the native library
 * on its own threads. Every call is main-safe; a failure is a
 * [TutaException] carrying the protocol's fixed code.
 *
 * One client per application is enough, and calls may overlap. Each call
 * resumes the [TutaSession] it is given; nothing is cached between calls.
 * Cancelling a call abandons its result, not the operation, which runs to
 * its end (at most 90 seconds): a send is never cut off half-way.
 *
 * @param clientName the name Tuta lists this app's sessions under.
 */
class TutaClient private constructor(private val native: TutaFfi) : AutoCloseable {
    constructor(clientName: String) : this(open { TutaFfi(clientName) })

    /**
     * One raw protocol request object in, its reply object out
     * (`{"version":1,"result":...}` or `{"version":1,"error":{"code":...}}`),
     * exactly as `tuta-helper` would answer it.
     */
    suspend fun rawRequest(request: String): String = native.request(request)

    /** Sign in. A TOTP code is good for one sign-in. */
    suspend fun login(email: String, password: String, totp: String? = null): TutaSession {
        val result = call("login") {
            put("email", email)
            put("password", password)
            totp?.let { put("totp", it) }
        }
        val session = result["session"] as? JsonObject ?: throw TutaException.of(TutaErrorCode.INCOMPLETE_RESPONSE.wire)
        return TutaSession.of(session)
    }

    /**
     * The folder tree, the labels and a page of [folder] (the Inbox when
     * null), newest first: at most [limit] mails from [offset].
     */
    suspend fun sync(session: TutaSession, folder: String? = null, limit: Int, offset: Int = 0): SyncPage =
        decode(SyncPage.serializer()) {
            call("sync", session) {
                folder?.let { put("folder", it) }
                put("limit", limit)
                put("offset", offset)
            }
        }

    /** A mail, decrypted. */
    suspend fun message(session: TutaSession, id: String): Message =
        decode(Message.serializer()) { call("message", session) { put("id", id) } }

    /** Mark up to 50 mails read or unread. */
    suspend fun markRead(session: TutaSession, ids: List<String>, isRead: Boolean): List<IdOutcome> =
        outcomes(IdOutcome.serializer()) {
            call("mark_read", session) {
                put("ids", strings(ids))
                put("is_read", isRead)
            }
        }

    /** Move 1 to 50 mails into [destination]. */
    suspend fun move(session: TutaSession, ids: List<String>, destination: String): List<MoveOutcome> =
        outcomes(MoveOutcome.serializer()) {
            call("move", session) {
                put("ids", strings(ids))
                put("destination", destination)
            }
        }

    /**
     * Send a mail. [TutaErrorCode.SEND_UNCERTAIN] means it may have gone out:
     * never resend it.
     */
    suspend fun send(session: TutaSession, request: SendRequest): SendOutcome =
        decode(SendOutcome.serializer()) { call("send", session) { with(request) { fields() } } }

    /** Close [session] on the server. */
    suspend fun revoke(session: TutaSession) {
        call("revoke", session) {}
    }

    /** The account's labels. */
    suspend fun listLabels(session: TutaSession): List<Label> =
        decode(ListSerializer(Label.serializer())) { call("list_labels", session) {}.getValue("labels") }

    /** Create a folder (under [parent], or at the top level); returns its id. */
    suspend fun createFolder(session: TutaSession, name: String, parent: String? = null): String =
        id(call("create_folder", session) {
            put("name", name)
            parent?.let { put("parent", it) }
        })

    /**
     * Rename and/or re-parent a custom folder; [parent] `""` moves it to the
     * top level. At least one of [name] and [parent].
     */
    suspend fun renameFolder(session: TutaSession, id: String, name: String? = null, parent: String? = null) {
        call("rename_folder", session) {
            put("id", id)
            name?.let { put("name", it) }
            parent?.let { put("parent", it) }
        }
    }

    /** Delete a custom folder as the official sidebar does. */
    suspend fun deleteFolder(session: TutaSession, id: String): FolderDeletion =
        decode(FolderDeletion.serializer()) { call("delete_folder", session) { put("id", id) }.getValue("outcome") }

    /** Create a label with a `#rrggbb` [color]; returns its id. */
    suspend fun createLabel(session: TutaSession, name: String, color: String): String =
        id(call("create_label", session) {
            put("name", name)
            put("color", color)
        })

    /** Rename and/or recolour a label: at least one of [name] and [color]. */
    suspend fun updateLabel(session: TutaSession, id: String, name: String? = null, color: String? = null) {
        call("update_label", session) {
            put("id", id)
            name?.let { put("name", it) }
            color?.let { put("color", it) }
        }
    }

    suspend fun deleteLabel(session: TutaSession, id: String) {
        call("delete_label", session) { put("id", id) }
    }

    /** Add and remove labels on 1 to 50 mails. */
    suspend fun applyLabels(
        session: TutaSession,
        ids: List<String>,
        add: List<String>,
        remove: List<String>,
    ): List<IdOutcome> = outcomes(IdOutcome.serializer()) {
        call("apply_labels", session) {
            put("ids", strings(ids))
            put("add", strings(add))
            put("remove", strings(remove))
        }
    }

    /** Delete 1 to 50 mails for good from Trash, Spam or a folder inside them. */
    suspend fun delete(session: TutaSession, ids: List<String>, folder: String): List<IdOutcome> =
        outcomes(IdOutcome.serializer()) {
            call("delete", session) {
                put("ids", strings(ids))
                put("folder", folder)
            }
        }

    /** Empty Trash or Spam; returns how many mails it held. */
    suspend fun emptyFolder(session: TutaSession, id: String): Long {
        val deleted = call("empty_folder", session) { put("id", id) }["deleted"]
        return (deleted as? JsonPrimitive)?.longOrNull ?: throw TutaException.of(TutaErrorCode.INCOMPLETE_RESPONSE.wire)
    }

    /** Save a draft; returns its id. */
    suspend fun saveDraft(session: TutaSession, draft: DraftRequest): String =
        id(call("save_draft", session) { with(draft) { fields() } })

    /** Discard a draft through Trash. */
    suspend fun deleteDraft(session: TutaSession, id: String) {
        call("delete_draft", session) { put("id", id) }
    }

    /** The contact passwords of up to 100 [addresses], per distinct address in order. */
    suspend fun contactPasswords(session: TutaSession, addresses: List<String>): List<ContactPassword> =
        decode(ListSerializer(ContactPassword.serializer())) {
            call("contact_passwords", session) { put("addresses", strings(addresses)) }.getValue("recipients")
        }

    /** Keep up to 100 passwords on their contacts, by address. */
    suspend fun storeContactPasswords(session: TutaSession, passwords: Map<String, String>) {
        call("store_contact_passwords", session) {
            put("passwords", JsonObject(passwords.mapValues { JsonPrimitive(it.value) }))
        }
    }

    /**
     * Import one RFC 5322 message into [folder] (Legend and Unlimited plans);
     * returns the new mail's id, or null when the server had not listed it
     * yet.
     */
    suspend fun import(session: TutaSession, folder: String, mime: ByteArray, unread: Boolean = false): String? {
        val result = call("import", session) {
            put("folder", folder)
            put("mime_base64", Base64.encode(mime))
            put("unread", unread)
        }
        return (result["id"] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content
    }

    /**
     * Tuta's push channel for [session]: [TutaWatchEvent]s until the flow is
     * cancelled. A watch that cannot go on fails the flow with its
     * [TutaException] (`session_revoked`, `client_outdated`,
     * `transport_failed`, `watch_failed`).
     */
    fun watch(session: TutaSession): Flow<TutaWatchEvent> = callbackFlow {
        val listener = object : WatchListener {
            override fun onLine(line: String): Boolean = try {
                val reply = TutaJson.parseToJsonElement(line).jsonObject
                val error = reply["error"]
                if (error != null) {
                    close(TutaException.of(error.jsonObject.getValue("code").jsonPrimitive.content))
                    false
                } else {
                    val event = TutaWatchEvent.of(reply)
                    event == null || trySend(event).isSuccess
                }
            } catch (failure: Exception) {
                close(failure)
                false
            }

            override fun onClosed() {
                channel.close()
            }
        }
        val handle = native.watch(session.json, listener)
        awaitClose {
            handle.stop()
            handle.close()
        }
    }.buffer(Channel.UNLIMITED)

    /** Release the native client; running watches end. */
    override fun close() = native.close()

    private suspend fun call(op: String, session: TutaSession? = null, fields: JsonObjectBuilder.() -> Unit): JsonObject {
        val request = buildJsonObject {
            put("version", PROTOCOL_VERSION)
            put("op", op)
            session?.let { put("session", it.element) }
            fields()
        }
        val line = native.request(request.toString())
        return withContext(Dispatchers.Default) { result(line) }
    }

    private fun result(line: String): JsonObject {
        val reply = TutaJson.parseToJsonElement(line).jsonObject
        reply["error"]?.let { throw TutaException.of(it.jsonObject.getValue("code").jsonPrimitive.content) }
        return reply["result"] as? JsonObject ?: throw TutaException.of(TutaErrorCode.INCOMPLETE_RESPONSE.wire)
    }

    private suspend fun <T> decode(strategy: DeserializationStrategy<T>, element: suspend () -> JsonElement): T {
        val value = element()
        return withContext(Dispatchers.Default) {
            try {
                TutaJson.decodeFromJsonElement(strategy, value)
            } catch (_: IllegalArgumentException) {
                throw TutaException.of(TutaErrorCode.INCOMPLETE_RESPONSE.wire)
            }
        }
    }

    private suspend fun <T> outcomes(strategy: KSerializer<T>, result: suspend () -> JsonObject): List<T> =
        decode(ListSerializer(strategy)) { result().getValue("outcomes") }

    private fun id(result: JsonObject): String =
        (result["id"] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content
            ?: throw TutaException.of(TutaErrorCode.INCOMPLETE_RESPONSE.wire)

    private fun strings(values: List<String>) = JsonArray(values.map(::JsonPrimitive))

    companion object {
        /** The protocol version this layer speaks. */
        const val PROTOCOL_VERSION: Int = 1

        /**
         * A client for another API origin, for tests against a stand-in
         * server.
         */
        fun withBaseUrl(clientName: String, baseUrl: String): TutaClient =
            TutaClient(open { TutaFfi.withBaseUrl(clientName, baseUrl) })

        /** Every code the native library can answer with, in its order. */
        fun nativeErrorCodes(): List<String> = ffiErrorCodes()

        /** The protocol version of the native library. */
        fun nativeProtocolVersion(): Int = ffiProtocolVersion().toInt()

        private inline fun open(make: () -> TutaFfi): TutaFfi = try {
            make()
        } catch (failure: NativeException.Failed) {
            throw TutaException.of(failure.code)
        }
    }
}
