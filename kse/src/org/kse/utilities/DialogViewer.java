package org.kse.utilities;

import java.awt.event.WindowEvent;
import java.security.Security;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.gui.JEscDialog;

import com.formdev.flatlaf.FlatLightLaf;

/**
 * This is a helper class for quickly viewing KSE dialogs (mainly for testing purposes during development).
 *
 */
public class DialogViewer {

	private DialogViewer() {
	}

	/**
	 * Add BC provider and set l&f (only required when BC is needed before calling the run() method)
	 */
	public static void prepare() throws UnsupportedLookAndFeelException {
		UIManager.setLookAndFeel(new FlatLightLaf());
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Create environment for showing the given dialog
	 */
	public static void run(final JEscDialog dialog) throws UnsupportedLookAndFeelException {

		prepare();

		SwingUtilities.updateComponentTreeUI(dialog);

		SwingUtilities.invokeLater(() -> {

			dialog.addWindowListener(new java.awt.event.WindowAdapter() {
				@Override
				public void windowClosing(java.awt.event.WindowEvent e) {
					super.windowClosing(e);
					System.exit(0);
				}

				@Override
				public void windowDeactivated(WindowEvent e) {
					super.windowDeactivated(e);
					System.exit(0);
				}
			});
			dialog.setLocationRelativeTo(null);
			dialog.setVisible(true);
		});
	}
}
