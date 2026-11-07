package org.tunaos.tuta

import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.ServerSocket
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The Kotlin layer against the host-built native library: requests are
 * checked by the same Rust code `tuta-helper` runs, so every request here
 * that fails before any I/O proves the layer's field names and shapes
 * against the real parser. Nothing reaches Tuta: the client points at a
 * local port.
 */
class NativeContractTest {
    // A port nothing listens on: any request that gets as far as the network
    // fails at once with transport_failed.
    private val closedUrl: String = ServerSocket(0).use { "http://127.0.0.1:${it.localPort}" }
    private val client = TutaClient.withBaseUrl("tuta-sdk-jvm-test", closedUrl)

    private val session = TutaSession.fromJson(
        """{"login":"a@tuta.com","user_id":"u","access_token":"AAECAwQFBgcICQoLDA0ODw","encrypted_passphrase_key":[1,2]}""",
    )

    @AfterTest
    fun close() = client.close()

    private inline fun <reified T : TutaException> fails(code: TutaErrorCode, noinline block: suspend () -> Unit) {
        val failure = assertFailsWith<T> { runBlocking { block() } }
        assertEquals(code, failure.code)
        assertEquals(code.wire, failure.message)
    }

    private fun replyCode(reply: String): String? {
        val reply = Json.parseToJsonElement(reply).jsonObject
        assertEquals(1, reply.getValue("version").jsonPrimitive.content.toInt())
        return reply["error"]?.jsonObject?.getValue("code")?.jsonPrimitive?.content
    }

    @Test
    fun theErrorCodesMatchTheNativeLibrary() {
        assertEquals(
            TutaClient.nativeErrorCodes(),
            TutaErrorCode.entries.filter { it != TutaErrorCode.UNKNOWN }.map { it.wire },
        )
        assertEquals(TutaClient.PROTOCOL_VERSION, TutaClient.nativeProtocolVersion())
    }

    @Test
    fun rawRequestsAnswerExactlyAsTheHelper() = runBlocking {
        assertEquals("""{"error":{"code":"invalid_request"},"version":1}""", client.rawRequest("garbage"))
        assertEquals("unsupported_version", replyCode(client.rawRequest("""{"version":2,"op":"revoke","session":${session.json}}""")))
        assertEquals("invalid_request", replyCode(client.rawRequest("""{"version":1,"op":"star"}""")))
        val watch = """{"version":1,"op":"watch","session":${session.json}}"""
        assertEquals("invalid_request", replyCode(client.rawRequest(watch)))
    }

    @Test
    fun codesMapToTheirFamilies() {
        assertIs<TutaException.Session>(TutaException.of("session_revoked"))
        assertIs<TutaException.Transport>(TutaException.of("timeout"))
        assertIs<TutaException.Content>(TutaException.of("decryption_failed"))
        assertIs<TutaException.InvalidRequest>(TutaException.of("invalid_batch"))
        assertIs<TutaException.Send>(TutaException.of("send_uncertain"))
        assertIs<TutaException.Contacts>(TutaException.of("contact_save_failed"))
        assertIs<TutaException.Folders>(TutaException.of("limit_reached"))
        assertIs<TutaException.Delete>(TutaException.of("not_trash_or_spam"))
        assertIs<TutaException.Drafts>(TutaException.of("not_a_draft"))
        assertIs<TutaException.Import>(TutaException.of("import_refused"))
        assertIs<TutaException.Watch>(TutaException.of("watch_failed"))
        val unknown = assertIs<TutaException.Unknown>(TutaException.of("brand_new"))
        assertEquals(TutaErrorCode.UNKNOWN, unknown.code)
        assertEquals("brand_new", unknown.wireCode)
    }

    @Test
    fun offlineChecksRefuseBadRequestsBeforeAnyIo() {
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_ID) { client.markRead(session, listOf("nope"), true) }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_BATCH) { client.move(session, emptyList(), "a/b") }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_BATCH) {
            client.delete(session, (1..51).map { "l/$it" }, "t/t")
        }
        fails<TutaException.Folders>(TutaErrorCode.INVALID_COLOR) { client.createLabel(session, "x", "red") }
        fails<TutaException.Folders>(TutaErrorCode.INVALID_NAME) { client.createFolder(session, "  ") }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_REQUEST) { client.renameFolder(session, "a/b") }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_ID) { client.deleteDraft(session, "nope") }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_ID) {
            client.import(session, "nope", "Subject: x\r\n\r\nx".toByteArray())
        }
        fails<TutaException.Import>(TutaErrorCode.IMPORT_INVALID) { client.import(session, "a/b", ByteArray(0)) }
        fails<TutaException.Send>(TutaErrorCode.INVALID_RECIPIENT) {
            client.contactPasswords(session, listOf("not an address"))
        }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_ID) { client.getMime(session, "nope") }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_PAGE) {
            client.search(session, SearchQuery(keyword = "x"), limit = 0)
        }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_REQUEST) { client.search(session, SearchQuery()) }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_REQUEST) {
            client.search(session, SearchQuery(afterMs = 5, beforeMs = 5))
        }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_REQUEST) {
            client.search(session, SearchQuery(subject = "x"), folder = "a/b", cursor = "c/d/e")
        }
        fails<TutaException.Folders>(TutaErrorCode.FOLDER_NOT_FOUND) {
            client.search(session, SearchQuery(isUnread = true), folder = "nope")
        }
    }

    @Test
    fun sendAndDraftRequestsMatchTheNativeParser() {
        val reply = SendRequest(
            sender = "a@tuta.com",
            senderName = "A",
            to = listOf(Recipient("B", "b@example.org")),
            subject = "s",
            bodyHtml = "<p>b</p>",
            confidential = true,
            passwords = mapOf("b@example.org" to "pw"),
            attachments = listOf(OutgoingAttachment("a.txt", "text/plain", byteArrayOf(1, 2, 3), cid = "c1")),
            // An action without a parent: refused after parsing, before I/O.
            thread = MailThread(action = ThreadAction.REPLY),
        )
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_THREAD) { client.send(session, reply) }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_THREAD) {
            client.send(session, SendRequest("a@tuta.com", "", subject = "", bodyHtml = "", confidential = false, thread = MailThread(inReplyTo = "a b")))
        }
        val draft = DraftRequest(
            draftId = "list/element",
            sender = "a@tuta.com",
            senderName = "",
            cc = listOf(Recipient("", "nope")),
            subject = "",
            bodyHtml = "",
            confidential = false,
        )
        fails<TutaException.Send>(TutaErrorCode.INVALID_RECIPIENT) { client.saveDraft(session, draft) }
        fails<TutaException.InvalidRequest>(TutaErrorCode.INVALID_ID) {
            client.saveDraft(session, DraftRequest("elem", "a@tuta.com", "", subject = "", bodyHtml = "", confidential = false))
        }
    }

    @Test
    fun emptyContactListsAnswerWithoutTheNetwork() = runBlocking {
        assertEquals(emptyList(), client.contactPasswords(session, emptyList()))
        client.storeContactPasswords(session, emptyMap())
    }

    @Test
    fun aPendingSignInIsHandedBackForTheCode() {
        val pending = TutaPendingSession(Json.parseToJsonElement(session.json).jsonObject)
        assertEquals("TutaPendingSession(<redacted>)", pending.toString())
        fun attempt(email: String = "a@tuta.com", totp: String?) =
            assertFailsWith<TutaException> { runBlocking { client.login(email, "password", totp, pending) } }

        val waiting = attempt(totp = null)
        assertEquals(TutaErrorCode.SECOND_FACTOR_REQUIRED, waiting.code)
        assertEquals("a@tuta.com", waiting.pendingSession?.login)
        val malformed = attempt(totp = "12a")
        assertEquals(TutaErrorCode.INVALID_TOTP, malformed.code)
        assertEquals("a@tuta.com", malformed.pendingSession?.login)
        // The code goes to the same session; the outage keeps it for a retry.
        val offline = attempt(totp = "123456")
        assertIs<TutaException.Transport>(offline)
        assertEquals("a@tuta.com", offline.pendingSession?.login)
        val otherAddress = attempt(email = "eve@tuta.com", totp = "123456")
        assertEquals(TutaErrorCode.INVALID_REQUEST, otherAddress.code)
        assertNull(otherAddress.pendingSession)
        assertIs<TutaException.Transport>(TutaException.of("rate_limited"))
        assertIs<TutaException.Session>(TutaException.of("pending_session_expired"))
    }

    @Test
    fun aPendingSignInCanBeCancelled() {
        // A token that holds no session id: refused before any I/O.
        val malformed = TutaPendingSession(
            Json.parseToJsonElement(
                """{"login":"a@tuta.com","user_id":"u","access_token":"t","encrypted_passphrase_key":[]}""",
            ).jsonObject,
        )
        fails<TutaException.Session>(TutaErrorCode.SESSION_INVALID) { client.cancelSignIn(malformed) }
        // A real one goes to the server, which is not there.
        val pending = TutaPendingSession(Json.parseToJsonElement(session.json).jsonObject)
        fails<TutaException.Transport>(TutaErrorCode.TRANSPORT_FAILED) { client.cancelSignIn(pending) }
    }

    @Test
    fun anUnreachableServerIsATransportFailure() {
        fails<TutaException.Transport>(TutaErrorCode.TRANSPORT_FAILED) { client.login("a@tuta.com", "password") }
        fails<TutaException.Transport>(TutaErrorCode.TRANSPORT_FAILED) { client.sync(session, limit = 10) }
    }

    @Test
    fun sessionsAreCheckedAndRedacted() {
        assertEquals("a@tuta.com", session.login)
        assertEquals("u", session.userId)
        assertEquals("TutaSession(login=<redacted>)", session.toString())
        assertEquals(session, TutaSession.fromJson(session.json))
        fails<TutaException.Session>(TutaErrorCode.SESSION_INVALID) { TutaSession.fromJson("{") }
        fails<TutaException.Session>(TutaErrorCode.SESSION_INVALID) { TutaSession.fromJson("""{"login":"a"}""") }
    }

    @Test
    fun aWatchThatCannotConnectFailsWithItsCode() = runBlocking {
        val failure = assertFailsWith<TutaException.Transport> {
            withTimeout(30_000) { client.watch(session).toList() }
        }
        assertEquals(TutaErrorCode.TRANSPORT_FAILED, failure.code)
    }

    @Test
    fun cancellingAWatchStopsIt() = runBlocking {
        // A server that accepts and never answers: the watch waits until the
        // flow is cancelled.
        ServerSocket(0).use { silent ->
            TutaClient.withBaseUrl("tuta-sdk-jvm-test", "http://127.0.0.1:${silent.localPort}").use { waiting ->
                val events = withTimeoutOrNull(500) { waiting.watch(session).toList() }
                assertNull(events, "the watch was still waiting")
            }
        }
    }

    @Test
    fun resultsDecodeLeniently() {
        val page = TutaJson.decodeFromString(
            SyncPage.serializer(),
            """
            {"folders":[{"id":"f/1","role":"inbox","label":"Inbox","parent":""},
                        {"id":"f/2","role":"brand_new","label":"X","parent":"f/1","extra":1}],
             "labels":[{"id":"l/1","name":"L","color":"#ff0000"}],
             "messages":[{"id":"m/1","subject":"s","date_ms":5,"sender":{"name":"A","address":"a@x"},
                          "recipient":null,"is_unread":true,"confidential":true,"conversation":"c",
                          "message_id":null,"has_attachments":false,"reply_type":0,"labels":["l/1"]}],
             "folder":"f/1","exists":1,"all_ids":["m/1"],"offset":0}
            """,
        )
        assertEquals(FolderRole.INBOX, page.folders[0].role)
        assertNull(page.folders[0].parent)
        assertEquals(FolderRole.OTHER, page.folders[1].role)
        assertEquals("f/1", page.folders[1].parent)
        assertEquals(listOf("l/1"), page.messages.single().labels)
        assertTrue(page.messages.single().header.isUnread)
        val outcome = TutaJson.decodeFromString(IdOutcome.serializer(), """{"id":"m/1","code":"not_attempted"}""")
        assertTrue(!outcome.isApplied && !outcome.isAttempted && outcome.error == null)
        val failed = TutaJson.decodeFromString(IdOutcome.serializer(), """{"id":"m/1","code":"transport_failed"}""")
        assertIs<TutaException.Transport>(failed.error)
        val search = TutaJson.decodeFromString(
            SearchPage.serializer(),
            """
            {"messages":[{"id":"m/1","subject":"s","date_ms":5,"sender":{"name":"A","address":"a@x"},
                          "recipient":null,"is_unread":false,"confidential":true,"conversation":"c",
                          "message_id":"x@y","has_attachments":true,"reply_type":1,"labels":[],
                          "folder":"f/1","new_field":2}],
             "next_cursor":"f/1/AAAA","scanned":3}
            """,
        )
        assertEquals("f/1", search.messages.single().folder)
        assertEquals("m/1", search.messages.single().mail.header.id)
        assertEquals("f/1/AAAA", search.nextCursor)
        assertEquals(3L, search.scanned)
        val done = TutaJson.decodeFromString(SearchPage.serializer(), """{"messages":[],"next_cursor":null,"scanned":0}""")
        assertNull(done.nextCursor)
    }
}
