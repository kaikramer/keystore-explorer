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

import java.io.File;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.text.MessageFormat;

import javax.swing.JOptionPane;

import org.kse.AuthorityCertificates;
import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreLoadException;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.gui.password.DGetPassword;

/**
 * Abstract base class for actions that utilize authority certificates.
 *
 */
public abstract class AuthorityCertificatesAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public AuthorityCertificatesAction(KseFrame kseFrame) {
		super(kseFrame);
	}

	/**
	 * Get CA Certificates KeyStore.
	 *
	 * @return KeyStore or null if unavailable
	 */
	protected KeyStore getCaCertificates() {
		AuthorityCertificates authorityCertificates = AuthorityCertificates.getInstance();

		KeyStore caCertificates = null;

		if (applicationSettings.getUseCaCertificates()) {
			caCertificates = authorityCertificates.getCaCertificates();

			if (caCertificates == null) {
				caCertificates = loadCaCertificatesKeyStore();

				if (caCertificates != null) {
					authorityCertificates.setCaCertificates(caCertificates);
				}
			}
		}

		return caCertificates;
	}

	/**
	 * Get Windows Trusted Root Certificates KeyStore.
	 *
	 * @return KeyStore or null if unavailable
	 * @throws CryptoException
	 *             If a problem occurred getting the KeyStore
	 */
	protected KeyStore getWindowsTrustedRootCertificates() throws CryptoException {
		AuthorityCertificates authorityCertificates = AuthorityCertificates.getInstance();

		KeyStore windowsTrustedRootCertificates = null;

		if (applicationSettings.getUseWindowsTrustedRootCertificates()) {
			windowsTrustedRootCertificates = authorityCertificates.getWindowsTrustedRootCertificates();
		}

		return windowsTrustedRootCertificates;
	}

	private KeyStore loadCaCertificatesKeyStore() {
		File caCertificatesFile = applicationSettings.getCaCertificatesFile();

		KeyStore caCertificatesKeyStore = null;
		try {

			// first try to open cacerts with default password
			try {
				Password password = new Password(AuthorityCertificates.CACERTS_DEFAULT_PWD.toCharArray());
				caCertificatesKeyStore = KeyStoreUtil.load(caCertificatesFile, password);
				if (caCertificatesFile != null) {
					return caCertificatesKeyStore;
				}
			} catch (KeyStoreLoadException ex) {
				// not default password, continue with password dialog
			}

			DGetPassword dGetPassword = new DGetPassword(frame,
					res.getString("AuthorityCertificatesAction.CaCertificatesKeyStorePassword.Title")
					);
			dGetPassword.setLocationRelativeTo(frame);
			dGetPassword.setVisible(true);
			Password password = dGetPassword.getPassword();

			if (password == null) {
				return null;
			}

			try {
				caCertificatesKeyStore = KeyStoreUtil.load(caCertificatesFile, password);
			} catch (KeyStoreLoadException ex) {
				String problemStr = MessageFormat.format(
						res.getString("AuthorityCertificatesAction.NoOpenCaCertificatesKeyStore.Problem"),
						ex.getKeyStoreType(), caCertificatesFile.getName());

				String[] causes = new String[] {
						res.getString("AuthorityCertificatesAction.PasswordIncorrectKeyStore.Cause"),
						res.getString("AuthorityCertificatesAction.CorruptedKeyStore.Cause") };

				Problem problem = new Problem(problemStr, causes, ex);

				DProblem dProblem = new DProblem(frame,
						res.getString("AuthorityCertificatesAction.ProblemOpeningCaCertificatesKeyStore.Title"),
						problem);
				dProblem.setLocationRelativeTo(frame);
				dProblem.setVisible(true);

				return null;
			}

			if (caCertificatesKeyStore == null) {
				JOptionPane.showMessageDialog(frame, MessageFormat.format(
						res.getString("AuthorityCertificatesAction.FileNotRecognisedType.message"),
						caCertificatesFile.getName()), res
						.getString("AuthorityCertificatesAction.OpenCaCertificatesKeyStore.Title"),
						JOptionPane.WARNING_MESSAGE);
				return null;
			}

			return caCertificatesKeyStore;
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(frame, MessageFormat.format(
					res.getString("AuthorityCertificatesAction.NoReadFile.message"), caCertificatesFile), res
					.getString("AuthorityCertificatesAction.OpenCaCertificatesKeyStore.Title"),
					JOptionPane.WARNING_MESSAGE);
			return null;
		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return null;
		}
	}
}
