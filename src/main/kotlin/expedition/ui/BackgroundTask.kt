package expedition.ui

import java.awt.Component
import javax.swing.AbstractButton
import javax.swing.JOptionPane
import javax.swing.SwingUtilities

/** Runs blocking file/registry work off the EDT, showing a busy state and reporting errors. */
object BackgroundTask {
    /**
     * Disables [button] (showing [busyText]) while [work] runs on the UI worker, then on the EDT
     * restores it, runs [afterSuccess] and shows the message [work] returned, or an error dialog.
     */
    fun run(
        parent: Component,
        button: AbstractButton?,
        busyText: String,
        failureLabel: String,
        work: () -> String,
        afterSuccess: () -> Unit = {},
    ) {
        val originalText = button?.text
        button?.apply { isEnabled = false; text = busyText }
        DisplayLimit.worker.execute {
            val outcome = try { Result.success(work()) } catch (e: Throwable) { Result.failure(e) }
            SwingUtilities.invokeLater {
                button?.apply { isEnabled = true; text = originalText }
                outcome.fold(
                    onSuccess = { msg -> afterSuccess(); JOptionPane.showMessageDialog(parent, msg) },
                    onFailure = { e -> JOptionPane.showMessageDialog(parent, "$failureLabel failed: ${e.message}", "Error", JOptionPane.ERROR_MESSAGE) },
                )
            }
        }
    }
}
