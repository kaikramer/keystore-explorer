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
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewCertificate;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to import a CA Reply into the selected key pair entry.
 *
 */
public class ImportCaReplyFromClipboardAction extends AuthorityCertificatesAction implements HistoryAction {
	private static final long serialVersionUID = 3536795359314369745L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ImportCaReplyFromClipboardAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("ImportCaReplyFromClipboardAction.statusbar"));
		putValue(NAME, res.getString("ImportCaReplyFromClipboardAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ImportCaReplyFromClipboardAction.tooltip"));
		putValue(SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ImportCaReplyFromClipboardAction.image")))));
	}

	@Override
	public String getHistoryDescription() {
		return (String) getValue(NAME);
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			String alias = kseFrame.getSelectedEntryAlias();

			Password password = getEntryPassword(alias, currentState);

			if (password == null) {
				return;
			}

			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();
			KeyStoreType keyStoreType = KeyStoreType.resolveJce(keyStore.getType());

			Key privateKey = keyStore.getKey(alias, password.toCharArray());

			X509Certificate[] certs = openCaReply();

			if (certs == null || certs.length == 0) {
				return;
			}

			certs = X509CertUtil.orderX509CertChain(certs);

			X509Certificate[] exitingEntryCerts = X509CertUtil.orderX509CertChain(X509CertUtil
					.convertCertificates(keyStore.getCertificateChain(alias)));

			if (!exitingEntryCerts[0].getPublicKey().equals(certs[0].getPublicKey())) {
				JOptionPane.showMessageDialog(frame, res.getString("ImportCaReplyFromClipboardAction.NoMatchPubKeyCaReply.message"),
						res.getString("ImportCaReplyFromClipboardAction.ImportCaReply.Title"), JOptionPane.WARNING_MESSAGE);
				return;
			}

			// Holds the new certificate chain for the entry should the import succeed
			X509Certificate[] newCertChain = null;

			if (!applicationSettings.getEnableImportCaReplyTrustCheck()) {
				newCertChain = certs;
			} else {
				KeyStore caCertificates = getCaCertificates();
				KeyStore windowsTrustedRootCertificates = getWindowsTrustedRootCertificates();

				// PKCS #7 reply - try and match the self-signed root with any
				// of the certificates in the CA Certificates or current KeyStore
				if (certs.length > 1) {
					X509Certificate rootCert = certs[certs.length - 1];
					String matchAlias = null;

					if (caCertificates != null) { // Match against CA Certificates KeyStore
						matchAlias = X509CertUtil.matchCertificate(caCertificates, rootCert);
					}

					// Match against Windows Trusted Root Certificates KeyStore
					if (windowsTrustedRootCertificates != null && matchAlias == null) {
						matchAlias = X509CertUtil.matchCertificate(windowsTrustedRootCertificates, rootCert);
					}

					if (matchAlias == null) { // Match against current KeyStore
						matchAlias = X509CertUtil.matchCertificate(keyStore, rootCert);
					}

					if (matchAlias == null) {
						// No match for the root certificate - display the certificate to the user for confirmation
						JOptionPane.showMessageDialog(frame,
								res.getString("ImportCaReplyFromClipboardAction.NoMatchRootCertCaReplyConfirm.message"),
								res.getString("ImportCaReplyFromClipboardAction.ImportCaReply.Title"),
								JOptionPane.INFORMATION_MESSAGE);

						DViewCertificate dViewCertificate = new DViewCertificate(frame, MessageFormat.format(
								res.getString("ImportCaReplyFromClipboardAction.CertDetailsFile.Title"), "Clipboard"),
								new X509Certificate[] { rootCert }, null, DViewCertificate.NONE);
						dViewCertificate.setLocationRelativeTo(frame);
						dViewCertificate.setVisible(true);

						int selected = JOptionPane.showConfirmDialog(frame,
								res.getString("ImportCaReplyFromClipboardAction.AcceptCaReply.message"),
								res.getString("ImportCaReplyFromClipboardAction.ImportCaReply.Title"), JOptionPane.YES_NO_OPTION);
						if (selected != JOptionPane.YES_OPTION) {
							return;
						}

						newCertChain = certs;
					} else {
						newCertChain = certs;
					}
				}
				// Single X.509 certificate reply - try and establish a chain of
				// trust from the certificate and ending with a root CA self-signed certificate
				else {
					// Establish trust against current KeyStore
					ArrayList<KeyStore> compKeyStores = new ArrayList<KeyStore>();
					compKeyStores.add(keyStore);

					if (caCertificates != null) {
						// Establish trust against CA Certificates KeyStore
						compKeyStores.add(caCertificates);
					}

					if (windowsTrustedRootCertificates != null) {
						// Establish trust against Windows Trusted Root Certificates KeyStore
						compKeyStores.add(windowsTrustedRootCertificates);
					}

					X509Certificate[] trustChain = X509CertUtil.establishTrust(certs[0],
							compKeyStores.toArray(new KeyStore[compKeyStores.size()]));

					if (trustChain != null) {
						newCertChain = trustChain;
					} else {
						// Cannot establish trust for the certificate - fail
						JOptionPane.showMessageDialog(frame,
								res.getString("ImportCaReplyFromClipboardAction.NoTrustCaReply.message"),
								res.getString("ImportCaReplyFromClipboardAction.ImportCaReply.Title"), JOptionPane.WARNING_MESSAGE);
						return;
					}
				}
			}

			if (keyStoreType.isFileBased()) {
				// TODO: why or when is delete actually necessary???
				keyStore.deleteEntry(alias);
				keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), newCertChain);
			} else {
				keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), newCertChain);
			}

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane.showMessageDialog(frame, res.getString("ImportCaReplyFromClipboardAction.ImportCaReplySuccessful.message"),
					res.getString("ImportCaReplyFromClipboardAction.ImportCaReply.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private X509Certificate[] openCaReply() {

		X509Certificate[] certs = null;

		try {

			// get clip board contents, but only string types, not files
			Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			Transferable t = clipboard.getContents(null);
			if (t.isDataFlavorSupported(DataFlavor.stringFlavor)) {
				String data;
				data = (String) t.getTransferData(DataFlavor.stringFlavor);
				ByteArrayInputStream bais = new ByteArrayInputStream(data.getBytes());

				// try to extract certs from clip board data
				certs = X509CertUtil.loadCertificates(bais);
				if (certs.length == 0) {
					JOptionPane.showMessageDialog(frame, MessageFormat.format(
							res.getString("ImportCaReplyFromClipboardAction.NoCertsFound.message"), "Clipboard"), res
							.getString("ImportCaReplyFromClipboardAction.OpenCaReply.Title"),
							JOptionPane.WARNING_MESSAGE);
				}
			}

			return certs;
		} catch (Exception ex) {
			String problemStr = MessageFormat.format(
					res.getString("ImportCaReplyFromClipboardAction.NoOpenCaReply.Problem"), "Clipboard");

			String[] causes = new String[] { res.getString("ImportCaReplyFromClipboardAction.NotCaReply.Cause"),
					res.getString("ImportCaReplyFromClipboardAction.CorruptedCaReply.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(frame,
					res.getString("ImportCaReplyFromClipboardAction.ProblemOpeningCaReply.Title"),
					problem);
			dProblem.setLocationRelativeTo(frame);
			dProblem.setVisible(true);

			return null;
		}
	}
}
