/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.apache.commons.io.FileUtils;
import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.privatekey.Pkcs8PbeType;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.importexport.DExportKeyPair;
import org.kse.gui.dialogs.importexport.DExportKeyPair.ExportFormat;
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
						getClass().getResource("images/exportkeypair.png"))));
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

			if (!dExportKeyPair.isExportSelected()) {
				return;
			}

			exportFile = dExportKeyPair.getExportFile();
			Password exportPassword = dExportKeyPair.getExportPassword();
			ExportFormat exportFormat = dExportKeyPair.getExportFormat();

			if (exportFormat == ExportFormat.PKCS12) {
				exportAsPkcs12(exportFile, alias, privateKey, certificates, exportPassword);
			} else {
				exportAsPem(exportFile, privateKey, certificates, exportPassword);
			}

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

	private void exportAsPkcs12(File exportFile, String alias, PrivateKey privateKey, Certificate[] certificates,
			Password exportPassword) throws CryptoException, IOException, KeyStoreException {

		KeyStore pkcs12 = KeyStoreUtil.create(KeyStoreType.PKCS12);

		certificates = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certificates));
		pkcs12.setKeyEntry(alias, privateKey, exportPassword.toCharArray(), certificates);

		KeyStoreUtil.save(pkcs12, exportFile, exportPassword);
	}

	private void exportAsPem(File exportFile, PrivateKey privateKey, Certificate[] certs, Password password)
			throws CryptoException, IOException {

		String pemEncodedPrivKey = null;
		if (password.isEmpty()) {
			pemEncodedPrivKey = Pkcs8Util.getPem(privateKey);
		} else {
			pemEncodedPrivKey = Pkcs8Util.getEncryptedPem(privateKey, Pkcs8PbeType.SHA1_3KEY_DESEDE, password);
		}

		X509Certificate[] orderedCerts = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));
		String pemEncodedCerts = X509CertUtil.getCertsEncodedX509Pem(orderedCerts);

		FileUtils.write(exportFile, pemEncodedPrivKey + pemEncodedCerts, StandardCharsets.US_ASCII);
	}
}
