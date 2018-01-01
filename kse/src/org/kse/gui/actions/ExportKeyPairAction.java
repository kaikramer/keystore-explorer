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

import java.awt.Toolkit;
import java.io.File;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.importexport.DExportKeyPair;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to export the selected key pair entry as PKCS #12.
 *
 */
public class ExportKeyPairAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExportKeyPairAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("ExportKeyPairAction.statusbar"));
		putValue(NAME, res.getString("ExportKeyPairAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExportKeyPairAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ExportKeyPairAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		File exportFile = null;

		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			String alias = kseFrame.getSelectedEntryAlias();

			Password password = getEntryPassword(alias, currentState);

			if (password == null) {
				return;
			}

			KeyStore keyStore = currentState.getKeyStore();

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			Certificate[] certificates = keyStore.getCertificateChain(alias);

			DExportKeyPair dExportKeyPair = new DExportKeyPair(frame, alias,
					applicationSettings.getPasswordQualityConfig());
			dExportKeyPair.setLocationRelativeTo(frame);
			dExportKeyPair.setVisible(true);

			if (!dExportKeyPair.exportSelected()) {
				return;
			}

			exportFile = dExportKeyPair.getExportFile();
			Password exportPassword = dExportKeyPair.getExportPassword();

			KeyStore pkcs12 = KeyStoreUtil.create(KeyStoreType.PKCS12);

			certificates = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certificates));
			pkcs12.setKeyEntry(alias, privateKey, exportPassword.toCharArray(), certificates);

			KeyStoreUtil.save(pkcs12, exportFile, exportPassword);

			JOptionPane.showMessageDialog(frame, res.getString("ExportKeyPairAction.ExportKeyPairSuccessful.message"),
					res.getString("ExportKeyPairAction.ExportKeyPair.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (FileNotFoundException ex) {
			String message = MessageFormat.format(res.getString("ExportKeyPairAction.NoWriteFile.message"), exportFile);
			JOptionPane.showMessageDialog(frame, message, res.getString("ExportKeyPairAction.ExportKeyPair.Title"),
					JOptionPane.WARNING_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
