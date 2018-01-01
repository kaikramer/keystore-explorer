/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.kse.gui.actions;

import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

import org.kse.ApplicationSettings;
import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.gui.password.DGetNewPassword;
import org.kse.gui.password.DGetPassword;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Abstract base class for all KeyStore Explorer actions.
 *
 */
public abstract class KeyStoreExplorerAction extends AbstractAction {
	private static final long serialVersionUID = 1L;

	/** Resource bundle */
	protected static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/actions/resources");

	/** KeyStore Explorer frame */
	protected KseFrame kseFrame;

	/** Underlying JFrame */
	protected JFrame frame;

	/** Application settings */
	protected ApplicationSettings applicationSettings;

	/**
	 * Construct a KeyStoreExplorerAction.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public KeyStoreExplorerAction(KseFrame kseFrame) {
		this.kseFrame = kseFrame;
		frame = kseFrame.getUnderlyingFrame();
		applicationSettings = kseFrame.getApplicationSettings();
	}

	/**
	 * Perform action. Calls doAction.
	 *
	 * @param evt
	 *            Action event
	 */
	@Override
	public void actionPerformed(ActionEvent evt) {
		try {
			kseFrame.setDefaultStatusBarText();
			CursorUtil.setCursorBusy(frame);
			kseFrame.getUnderlyingFrame().repaint();
			doAction();
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		} finally {
			CursorUtil.setCursorFree(frame);
		}
	}

	/**
	 * Do the action.
	 */
	protected abstract void doAction();

	/**
	 * Get an entry's password. Queries the KeyStore history first and, if the
	 * password is not found there, asks the user for it.
	 *
	 * @param alias
	 *            Entry alias
	 * @param state
	 *            KeyStore state
	 * @return Password or null if it could not be retrieved
	 */
	protected Password getEntryPassword(String alias, KeyStoreState state) {
		Password password = state.getEntryPassword(alias);

		if (password == null) {
			if (!KeyStoreType.resolveJce(state.getKeyStore().getType()).hasEntryPasswords()) {
				password = new Password((char[])null);
			} else {
				password = unlockEntry(alias, state);
			}
		}

		return password;
	}

	/**
	 * Unlock a key or key pair entry. Updates the KeyStore history with the
	 * password.
	 *
	 * @param alias
	 *            Entry's alias
	 * @param state
	 *            KeyStore state
	 * @return Key pair password if successful, null otherwise
	 */
	protected Password unlockEntry(String alias, KeyStoreState state) {
		try {
			KeyStore keyStore = state.getKeyStore();

			DGetPassword dGetPassword = new DGetPassword(frame, MessageFormat.format(
					res.getString("KeyStoreExplorerAction.UnlockEntry.Title"), alias));
			dGetPassword.setLocationRelativeTo(frame);
			dGetPassword.setVisible(true);
			Password password = dGetPassword.getPassword();

			if (password == null) {
				return null;
			}

			keyStore.getKey(alias, password.toCharArray()); // Test password is correct

			state.setEntryPassword(alias, password);
			kseFrame.updateControls(true);

			return password;
		} catch (GeneralSecurityException ex) {
			String problemStr = MessageFormat.format(res.getString("KeyStoreExplorerAction.NoUnlockEntry.Problem"),
					alias);

			String[] causes = new String[] { res.getString("KeyStoreExplorerAction.PasswordIncorrectEntry.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(frame,
					res.getString("KeyStoreExplorerAction.ProblemUnlockingEntry.Title"),
					problem);
			dProblem.setLocationRelativeTo(frame);
			dProblem.setVisible(true);

			return null;
		}
	}

	/**
	 * Open a certificate file.
	 *
	 * @param certificateFile
	 *            The certificate file
	 * @return The certificates found in the file or null if open failed
	 */
	protected X509Certificate[] openCertificate(File certificateFile) {
		try {
			FileInputStream is = new FileInputStream(certificateFile);
			return openCertificate(is, certificateFile.getName());
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("KeyStoreExplorerAction.NoReadFile.message"), certificateFile),
					res.getString("KeyStoreExplorerAction.OpenCertificate.Title"), JOptionPane.WARNING_MESSAGE);
			return null;
		}
	}

	/**
	 * Open a certificate input stream.
	 *
	 * @param certificateFile
	 *            The certificate file
	 * @return The certificates found in the file or null if open failed
	 */
	protected X509Certificate[] openCertificate(InputStream is, String name) {

		try {
			X509Certificate[] certs = X509CertUtil.loadCertificates(is);

			if (certs.length == 0) {
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("KeyStoreExplorerAction.NoCertsFound.message"), name),
						res.getString("KeyStoreExplorerAction.OpenCertificate.Title"), JOptionPane.WARNING_MESSAGE);
			}

			return certs;
		} catch (Exception ex) {
			String problemStr = MessageFormat.format(res.getString("KeyStoreExplorerAction.NoOpenCert.Problem"), name);

			String[] causes = new String[] { res.getString("KeyStoreExplorerAction.NotCert.Cause"),
					res.getString("KeyStoreExplorerAction.CorruptedCert.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(frame, res.getString("KeyStoreExplorerAction.ProblemOpeningCert.Title"),
					problem);
			dProblem.setLocationRelativeTo(frame);
			dProblem.setVisible(true);

			return null;
		}
	}

	/**
	 * Get a new KeyStore password.
	 *
	 * @return The new KeyStore password, or null if none entered by the user
	 */
	protected Password getNewKeyStorePassword() {
		DGetNewPassword dGetNewPassword = new DGetNewPassword(frame,
				res.getString("KeyStoreExplorerAction.SetKeyStorePassword.Title"),
				ApplicationSettings.getInstance().getPasswordQualityConfig());
		dGetNewPassword.setLocationRelativeTo(frame);
		dGetNewPassword.setVisible(true);

		Password password = dGetNewPassword.getPassword();

		return password;
	}

	/**
	 * Is the supplied KeyStore file open?
	 *
	 * @param keyStoreFile
	 *            KeyStore file
	 * @return True if it is
	 */
	protected boolean isKeyStoreFileOpen(File keyStoreFile) {
		KeyStoreHistory[] histories = kseFrame.getKeyStoreHistories();

		for (int i = 0; i < histories.length; i++) {
			File f = histories[i].getFile();

			if (f != null && f.equals(keyStoreFile)) {
				return true;
			}
		}

		return false;
	}
}
