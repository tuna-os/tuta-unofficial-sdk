package org.tunaos.tuta

/**
 * The protocol's fixed error codes, in the library's order (the README's
 * "Error codes" section). [wire] is the snake_case code on the wire;
 * [UNKNOWN] stands for a code this build does not know yet (a newer native
 * library).
 */
enum class TutaErrorCode(val wire: String, internal val category: Category) {
    // Sign-in and sessions.
    LOGIN_FAILED("login_failed", Category.SESSION),
    SECOND_FACTOR_REQUIRED("second_factor_required", Category.SESSION),
    SECOND_FACTOR_FAILED("second_factor_failed", Category.SESSION),
    INVALID_TOTP("invalid_totp", Category.SESSION),
    UNSUPPORTED_U2F("unsupported_u2f", Category.SESSION),
    UNSUPPORTED_WEBAUTHN("unsupported_webauthn", Category.SESSION),
    UNSUPPORTED_SECOND_FACTOR("unsupported_second_factor", Category.SESSION),
    RESUME_FAILED("resume_failed", Category.SESSION),
    SESSION_INVALID("session_invalid", Category.SESSION),
    SESSION_REVOKED("session_revoked", Category.SESSION),
    CLIENT_OUTDATED("client_outdated", Category.SESSION),

    /** A sign-in's pending session is gone on the server: sign in again. */
    PENDING_SESSION_EXPIRED("pending_session_expired", Category.SESSION),

    // Transport.
    TRANSPORT_FAILED("transport_failed", Category.TRANSPORT),
    REQUEST_FAILED("request_failed", Category.TRANSPORT),
    TIMEOUT("timeout", Category.TRANSPORT),

    /** Tuta is throttling sign-ins or requests: wait a few minutes, then retry. */
    RATE_LIMITED("rate_limited", Category.TRANSPORT),

    // Content.
    DECRYPTION_FAILED("decryption_failed", Category.CONTENT),
    UNSUPPORTED_LEGACY_BODY("unsupported_legacy_body", Category.CONTENT),
    ATTACHMENT_FAILED("attachment_failed", Category.CONTENT),
    BODY_TOO_LARGE("body_too_large", Category.CONTENT),
    INCOMPLETE_RESPONSE("incomplete_response", Category.CONTENT),

    // Requests.
    INVALID_REQUEST("invalid_request", Category.REQUEST),
    UNSUPPORTED_VERSION("unsupported_version", Category.REQUEST),
    INVALID_ID("invalid_id", Category.REQUEST),
    INVALID_PAGE("invalid_page", Category.REQUEST),
    INVALID_BATCH("invalid_batch", Category.REQUEST),
    INVALID_THREAD("invalid_thread", Category.REQUEST),

    // Sending.
    INVALID_RECIPIENT("invalid_recipient", Category.SEND),
    SENDER_UNKNOWN("sender_unknown", Category.SEND),
    RECIPIENT_NOT_FOUND("recipient_not_found", Category.SEND),
    PASSWORD_REQUIRED("password_required", Category.SEND),
    SECURE_EXTERNAL_SENDER_UNSUPPORTED("secure_external_sender_unsupported", Category.SEND),
    ORDINARY_DELIVERY_REQUIRES_CONSENT("ordinary_delivery_requires_consent", Category.SEND),
    SEND_FAILED("send_failed", Category.SEND),

    /** The mail may have gone out: never resend it. */
    SEND_UNCERTAIN("send_uncertain", Category.SEND),

    // Contacts and sessions.
    CONTACT_SAVE_FAILED("contact_save_failed", Category.CONTACTS),
    REVOKE_FAILED("revoke_failed", Category.SESSION),

    // Folders and labels.
    FOLDER_NOT_FOUND("folder_not_found", Category.FOLDERS),
    FOLDER_EXISTS("folder_exists", Category.FOLDERS),
    NOT_CUSTOM_FOLDER("not_custom_folder", Category.FOLDERS),
    INVALID_PARENT("invalid_parent", Category.FOLDERS),
    INVALID_NAME("invalid_name", Category.FOLDERS),
    OPERATION_STILL_ACTIVE("operation_still_active", Category.FOLDERS),
    FOLDER_FAILED("folder_failed", Category.FOLDERS),
    LABEL_NOT_FOUND("label_not_found", Category.FOLDERS),
    LABEL_EXISTS("label_exists", Category.FOLDERS),
    INVALID_COLOR("invalid_color", Category.FOLDERS),
    LABEL_FAILED("label_failed", Category.FOLDERS),
    LIMIT_REACHED("limit_reached", Category.FOLDERS),

    // Deleting.
    NOT_TRASH_OR_SPAM("not_trash_or_spam", Category.DELETE),
    DELETE_FAILED("delete_failed", Category.DELETE),

    // Drafts.
    DRAFT_NOT_FOUND("draft_not_found", Category.DRAFTS),
    NOT_A_DRAFT("not_a_draft", Category.DRAFTS),
    DRAFT_FAILED("draft_failed", Category.DRAFTS),

    // Importing.
    IMPORT_INVALID("import_invalid", Category.IMPORT),
    IMPORT_TOO_LARGE("import_too_large", Category.IMPORT),
    IMPORT_REFUSED("import_refused", Category.IMPORT),
    IMPORT_FAILED("import_failed", Category.IMPORT),

    // Watching.
    WATCH_FAILED("watch_failed", Category.WATCH),

    /** A code this build does not know. */
    UNKNOWN("", Category.UNKNOWN),
    ;

    internal enum class Category { SESSION, TRANSPORT, CONTENT, REQUEST, SEND, CONTACTS, FOLDERS, DELETE, DRAFTS, IMPORT, WATCH, UNKNOWN }

    companion object {
        private val byWire = entries.filter { it != UNKNOWN }.associateBy { it.wire }

        /** The code [wire] names, or [UNKNOWN]. */
        fun fromWire(wire: String): TutaErrorCode = byWire[wire] ?: UNKNOWN
    }
}

/**
 * A failed operation: one of the protocol's fixed codes, never server text.
 * The subclass is the code's family, so callers can catch a whole family
 * ([Session] means "sign in again" for most of its codes) or match on [code].
 * [message] is the wire code.
 */
sealed class TutaException(
    val code: TutaErrorCode,
    /** The code as the wire carried it (for [Unknown], the unknown code). */
    val wireCode: String,
) : Exception(wireCode) {
    /**
     * For a sign-in that is waiting on its second factor
     * ([TutaErrorCode.SECOND_FACTOR_REQUIRED], a refused or malformed code,
     * an outage or throttling during that step): the session to retry the
     * code on with [TutaClient.login]. Null when the sign-in must start over.
     */
    var pendingSession: TutaPendingSession? = null
        internal set

    /** Sign-in, resuming, revoking: `login_failed`, `session_revoked`, `client_outdated`, ... */
    class Session internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** No connection, an outage, throttling, or the 90-second limit. */
    class Transport internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** Mail that could not be decrypted or read. */
    class Content internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** A request refused before any I/O: a malformed id, page, batch or thread. */
    class InvalidRequest internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** A send that failed, or ([TutaErrorCode.SEND_UNCERTAIN]) may have gone out. */
    class Send internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** A contact password that could not be stored. */
    class Contacts internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** Folder and label management. */
    class Folders internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** Permanent deletes. */
    class Delete internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** Saving or discarding drafts. */
    class Drafts internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** Importing a MIME message. */
    class Import internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** The event bus could not be held. */
    class Watch internal constructor(code: TutaErrorCode) : TutaException(code, code.wire)

    /** A code this build does not know (a newer native library). */
    class Unknown internal constructor(wireCode: String) : TutaException(TutaErrorCode.UNKNOWN, wireCode)

    companion object {
        /** The exception for a wire code, carrying [pendingSession] when the reply had one. */
        internal fun of(wireCode: String, pendingSession: TutaPendingSession?): TutaException =
            of(wireCode).also { it.pendingSession = pendingSession }

        /** The exception for a wire code. */
        fun of(wireCode: String): TutaException {
            val code = TutaErrorCode.fromWire(wireCode)
            return when (code.category) {
                TutaErrorCode.Category.SESSION -> Session(code)
                TutaErrorCode.Category.TRANSPORT -> Transport(code)
                TutaErrorCode.Category.CONTENT -> Content(code)
                TutaErrorCode.Category.REQUEST -> InvalidRequest(code)
                TutaErrorCode.Category.SEND -> Send(code)
                TutaErrorCode.Category.CONTACTS -> Contacts(code)
                TutaErrorCode.Category.FOLDERS -> Folders(code)
                TutaErrorCode.Category.DELETE -> Delete(code)
                TutaErrorCode.Category.DRAFTS -> Drafts(code)
                TutaErrorCode.Category.IMPORT -> Import(code)
                TutaErrorCode.Category.WATCH -> Watch(code)
                TutaErrorCode.Category.UNKNOWN -> Unknown(wireCode)
            }
        }
    }
}
