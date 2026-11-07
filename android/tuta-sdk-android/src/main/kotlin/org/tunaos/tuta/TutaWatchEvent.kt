package org.tunaos.tuta

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** One change Tuta's event bus reported (README, "Watch"). Names folders only, never content. */
sealed interface TutaWatchEvent {
    /** The bus connected for the first time. */
    data object Ready : TutaWatchEvent

    /** The bus dropped and came back: resync. */
    data object Reconnect : TutaWatchEvent

    /** A folder or label was created, renamed, moved or deleted. */
    data object FoldersChanged : TutaWatchEvent

    /**
     * Mail in [folder] arrived, left or changed (read state, labels); a null
     * [folder] could not be told: resync everything.
     */
    data class MailChanged(val folder: String?) : TutaWatchEvent

    companion object {
        /** The event a watch line names, or null for one this build does not know. */
        internal fun of(line: JsonObject): TutaWatchEvent? = when ((line["event"] as? JsonPrimitive)?.content) {
            "ready" -> Ready
            "reconnect" -> Reconnect
            "folders_changed" -> FoldersChanged
            "mail_changed" -> MailChanged((line["folder"] as? JsonPrimitive)?.content?.ifEmpty { null })
            else -> null
        }
    }
}
