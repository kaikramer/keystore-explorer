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
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.CryptoException;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.importexport.DExportCertificates;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to export the selected trusted certificate entry.
 *
 */
public class ExportTrustedCertificateAction extends KeyStoreExplorerAction {

	private static final long serialVersionUID = 1L;
	private X509Certificate certFromConstructor;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExportTrustedCertificateAction(KseFrame kseFrame) {
		this(kseFrame, null);
	}

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 * @param cert
	 *            Certificate to be exported. If null, the currently selected keystore entry is used.
	 */
	public ExportTrustedCertificateAction(KseFrame kseFrame, X509Certificate cert) {
		super(kseFrame);

		this.certFromConstructor = cert;

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
	@Override
	protected void doAction() {
		File exportFile = null;

		try {
			DExportCertificates dExportCertificates = null;
			X509Certificate cert = null;
			if (certFromConstructor == null) {
				String alias = kseFrame.getSelectedEntryAlias();
				dExportCertificates = new DExportCertificates(frame, alias, false);
				cert = getCertificate(alias);
			} else {
				cert = certFromConstructor;
				dExportCertificates = new DExportCertificates(frame, X509CertUtil.getCertificateAlias(cert), false);
			}

			dExportCertificates.setLocationRelativeTo(frame);
			dExportCertificates.setVisible(true);

			if (!dExportCertificates.exportSelected()) {
				return;
			}

			exportFile = dExportCertificates.getExportFile();

			boolean pemEncode = dExportCertificates.pemEncode();

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
				encoded = X509CertUtil.getCertEncodedPkcs7(cert); // SPC is just DER PKCS #7
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
		try (FileOutputStream fos = new FileOutputStream(exportFile)) {
			fos.write(encoded);
			fos.flush();
		}
	}
}
