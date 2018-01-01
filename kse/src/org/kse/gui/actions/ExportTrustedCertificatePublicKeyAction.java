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
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.CryptoException;
import org.kse.crypto.publickey.OpenSslPubUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.importexport.DExportPublicKeyOpenSsl;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to export the selected trusted certificate entry's public key.
 *
 */
public class ExportTrustedCertificatePublicKeyAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExportTrustedCertificatePublicKeyAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("ExportTrustedCertificatePublicKeyAction.statusbar"));
		putValue(NAME, res.getString("ExportTrustedCertificatePublicKeyAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExportTrustedCertificatePublicKeyAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ExportTrustedCertificatePublicKeyAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		File exportFile = null;

		try {
			String alias = kseFrame.getSelectedEntryAlias();

			DExportPublicKeyOpenSsl dExportPublicKey = new DExportPublicKeyOpenSsl(frame, alias);
			dExportPublicKey.setLocationRelativeTo(frame);
			dExportPublicKey.setVisible(true);

			if (!dExportPublicKey.exportSelected()) {
				return;
			}

			exportFile = dExportPublicKey.getExportFile();
			boolean pemEncode = dExportPublicKey.pemEncode();

			PublicKey publicKey = getPublicKey(alias);

			byte[] encoded = null;

			if (pemEncode) {
				encoded = OpenSslPubUtil.getPem(publicKey).getBytes();
			} else {
				encoded = OpenSslPubUtil.get(publicKey);
			}

			exportEncodedPublicKey(encoded, exportFile);

			JOptionPane.showMessageDialog(frame,
					res.getString("ExportTrustedCertificatePublicKeyAction.ExportPublicKeyOpenSslSuccessful.message"),
					res.getString("ExportTrustedCertificatePublicKeyAction.ExportPublicKeyOpenSsl.Title"),
					JOptionPane.INFORMATION_MESSAGE);
		} catch (FileNotFoundException ex) {
			String message = MessageFormat.format(
					res.getString("ExportTrustedCertificatePublicKeyAction.NoWriteFile.message"), exportFile);

			JOptionPane.showMessageDialog(frame, message,
					res.getString("ExportTrustedCertificatePublicKeyAction.ExportPublicKeyOpenSsl.Title"),
					JOptionPane.WARNING_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private PublicKey getPublicKey(String alias) throws CryptoException {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStore keyStore = history.getCurrentState().getKeyStore();

			X509Certificate cert = X509CertUtil.convertCertificate(keyStore.getCertificate(alias));

			return cert.getPublicKey();
		} catch (KeyStoreException ex) {
			String message = MessageFormat.format(
					res.getString("ExportTrustedCertificatePublicKeyAction.NoAccessEntry.message"), alias);
			throw new CryptoException(message, ex);
		}
	}

	private void exportEncodedPublicKey(byte[] encoded, File exportFile) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(exportFile)) {
			fos.write(encoded);
			fos.flush();
		}
	}
}
