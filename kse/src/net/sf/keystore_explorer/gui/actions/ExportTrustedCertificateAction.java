/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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
package net.sf.keystore_explorer.gui.actions;

import java.awt.Toolkit;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.x509.X509CertUtil;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.importexport.DExportCertificates;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.io.SafeCloseUtil;

/**
 * Action to export the selected trusted certificate entry.
 * 
 */
public class ExportTrustedCertificateAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 * 
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExportTrustedCertificateAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("ExportTrustedCertificateAction.statusbar"));
		putValue(NAME, res.getString("ExportTrustedCertificateAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExportTrustedCertificateAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ExportTrustedCertificateAction.image")))));
	}

	/**
	 * Do action.
	 */
	protected void doAction() {
		File exportFile = null;

		try {
			String alias = kseFrame.getSelectedEntryAlias();

			DExportCertificates dExportCertificates = new DExportCertificates(frame, alias, false);
			dExportCertificates.setLocationRelativeTo(frame);
			dExportCertificates.setVisible(true);

			if (!dExportCertificates.exportSelected()) {
				return;
			}

			exportFile = dExportCertificates.getExportFile();

			boolean pemEncode = dExportCertificates.pemEncode();

			X509Certificate cert = getCertificate(alias);

			byte[] encoded = null;

			if (dExportCertificates.exportFormatX509()) {
				if (pemEncode) {
					encoded = X509CertUtil.getCertEncodedX509Pem(cert).getBytes();
				} else {
					encoded = X509CertUtil.getCertEncodedX509(cert);
				}
			} else if (dExportCertificates.exportFormatPkcs7()) {
				if (pemEncode) {
					encoded = X509CertUtil.getCertEncodedPkcs7Pem(cert).getBytes();
				} else {
					encoded = X509CertUtil.getCertEncodedPkcs7(cert);
				}
			} else if (dExportCertificates.exportFormatPkiPath()) {
				encoded = X509CertUtil.getCertEncodedPkiPath(cert);
			} else if (dExportCertificates.exportFormatSpc()) {
				encoded = X509CertUtil.getCertEncodedPkcs7(cert); // SPC is just
																	// DER PKCS
																	// #7
			}

			exportEncodedCertificate(encoded, exportFile);

			JOptionPane.showMessageDialog(frame,
					res.getString("ExportTrustedCertificateAction.ExportCertificateSuccessful.message"),
					res.getString("ExportTrustedCertificateAction.ExportCertificate.Title"),
					JOptionPane.INFORMATION_MESSAGE);
		} catch (FileNotFoundException ex) {
			String message = MessageFormat.format(res.getString("ExportTrustedCertificateAction.NoWriteFile.message"),
					exportFile);

			JOptionPane.showMessageDialog(frame, message,
					res.getString("ExportTrustedCertificateAction.ExportCertificate.Title"),
					JOptionPane.WARNING_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private X509Certificate getCertificate(String alias) throws CryptoException {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStore keyStore = history.getCurrentState().getKeyStore();

			X509Certificate cert = X509CertUtil.convertCertificate(keyStore.getCertificate(alias));

			return cert;
		} catch (KeyStoreException ex) {
			String message = MessageFormat.format(
					res.getString("ExportTrustedCertificateAction.NoAccessEntry.message"), alias);
			throw new CryptoException(message, ex);
		}
	}

	private void exportEncodedCertificate(byte[] encoded, File exportFile) throws IOException {
		FileOutputStream fos = null;

		try {
			fos = new FileOutputStream(exportFile);
			fos.write(encoded);
		} finally {
			SafeCloseUtil.close(fos);
		}
	}
}
