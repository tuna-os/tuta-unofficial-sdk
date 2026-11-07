package org.tunaos.tuta

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * A resumable session: the protocol's `session` object (`login`, `user_id`,
 * the access token and the encrypted passphrase key), as [TutaClient.login]
 * returned it.
 *
 * It is a credential: persist [json] only in encrypted storage (the Android
 * Keystore, EncryptedFile and the like), and never log it. [toString] is
 * redacted for that reason. Tuta does not rotate it; it stays valid until it
 * is revoked ([TutaClient.revoke]) or expires, which a call reports as
 * [TutaErrorCode.SESSION_REVOKED].
 */
class TutaSession private constructor(
    /** The session object, to persist and to restore with [fromJson]. */
    val json: String,
    internal val element: JsonObject,
) {
    /** The signed-in address. */
    val login: String = element.getValue("login").jsonPrimitive.content

    /** The account's user id. */
    val userId: String = element.getValue("user_id").jsonPrimitive.content

    override fun equals(other: Any?): Boolean = other is TutaSession && other.json == json

    override fun hashCode(): Int = json.hashCode()

    override fun toString(): String = "TutaSession(login=<redacted>)"

    companion object {
        /**
         * A session from its persisted [json]. Throws
         * [TutaException.Session] ([TutaErrorCode.SESSION_INVALID]) when it is
         * not a session object.
         */
        fun fromJson(json: String): TutaSession {
            val element = try {
                TutaJson.parseToJsonElement(json).jsonObject
            } catch (_: IllegalArgumentException) {
                throw TutaException.of(TutaErrorCode.SESSION_INVALID.wire)
            }
            return of(element)
        }

        internal fun of(element: JsonObject): TutaSession {
            val fields = setOf("login", "user_id", "access_token", "encrypted_passphrase_key")
            if (element.keys != fields || element.getValue("login") !is JsonPrimitive ||
                element.getValue("user_id") !is JsonPrimitive
            ) {
                throw TutaException.of(TutaErrorCode.SESSION_INVALID.wire)
            }
            return TutaSession(element.toString(), element)
        }
    }
}

/**
 * A sign-in waiting for its second factor: the session Tuta opened for it,
 * from [TutaException.pendingSession]. Pass it back to [TutaClient.login]
 * with the code, so the code completes this session instead of opening
 * another (Tuta throttles sign-ins). It is a credential: keep it in memory
 * only, never persist or log it, and drop it when the address or password
 * changes. An abandoned one expires on the server.
 */
class TutaPendingSession internal constructor(internal val element: JsonObject) {
    /** The address the sign-in is for. */
    val login: String = (element["login"] as? JsonPrimitive)?.content.orEmpty()

    override fun toString(): String = "TutaPendingSession(<redacted>)"
}
