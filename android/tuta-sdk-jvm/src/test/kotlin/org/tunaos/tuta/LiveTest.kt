package org.tunaos.tuta

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * One sign-in against Tuta's servers through the Kotlin layer, gated on
 * `TUTA_LIVE=1` with a test account's `TUTA_LIVE_EMAIL`,
 * `TUTA_LIVE_PASSWORD` and, when it has a second factor, `TUTA_LIVE_TOTP`
 * (a fresh code: each is good for one sign-in). It reads and changes
 * nothing but its own session, which it closes again. Never prints account
 * data.
 *
 * Ignored by default, so no build ever signs in by accident: remove the
 * `@Ignore` locally, export the variables and run
 * `./gradlew --no-daemon --no-configuration-cache :tuta-sdk-jvm:test --tests '*LiveTest*'`.
 */
class LiveTest {
    @Ignore("live: signs in to a real Tuta account; see the class comment")
    @Test
    fun signInSyncReadWatchAndRevoke() {
        assumeTrue("set TUTA_LIVE=1 to run", System.getenv("TUTA_LIVE") == "1")
        val email = System.getenv("TUTA_LIVE_EMAIL") ?: error("TUTA_LIVE_EMAIL")
        val password = System.getenv("TUTA_LIVE_PASSWORD") ?: error("TUTA_LIVE_PASSWORD")
        val totp = System.getenv("TUTA_LIVE_TOTP")?.takeIf { it.isNotBlank() }
        TutaClient("tuta-sdk-jvm-live").use { client ->
            runBlocking {
                val session = client.login(email, password, totp)
                try {
                    assertEquals(email.lowercase(), session.login.lowercase())
                    // A saved session restores to the same one.
                    val restored = TutaSession.fromJson(session.json)

                    val page = client.sync(restored, limit = 10)
                    val inbox = page.folders.single { it.role == FolderRole.INBOX }
                    assertEquals(inbox.id, page.folder)
                    assertTrue(page.messages.size <= 10)
                    assertTrue(page.allIds != null, "the first page lists every id")
                    for (role in listOf(FolderRole.SENT, FolderRole.TRASH, FolderRole.JUNK, FolderRole.DRAFTS)) {
                        assertTrue(page.folders.any { it.role == role }, "a $role folder")
                    }

                    page.messages.firstOrNull()?.let { newest ->
                        val message = client.message(restored, newest.header.id)
                        assertEquals(newest.header.id, message.header.id)
                        assertEquals(newest.header.subject, message.header.subject)
                    }
                    assertEquals(page.labels, client.listLabels(restored))

                    val ready = withTimeout(60_000) { client.watch(restored).first() }
                    assertEquals(TutaWatchEvent.Ready, ready)
                } finally {
                    client.revoke(session)
                }
                val revoked = runCatching { client.sync(session, limit = 1) }.exceptionOrNull()
                assertEquals(TutaErrorCode.SESSION_REVOKED, (revoked as? TutaException)?.code)
            }
        }
    }
}
