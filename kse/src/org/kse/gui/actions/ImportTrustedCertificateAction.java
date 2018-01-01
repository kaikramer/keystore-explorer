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
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DGetAlias;
import org.kse.gui.dialogs.DViewCertificate;
import org.kse.gui.error.DError;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to import a trusted certificate.
 *
 */
public class ImportTrustedCertificateAction extends AuthorityCertificatesAction implements HistoryAction {
	private static final long serialVersionUID = 1L;
	private X509Certificate trustCertFromConstructor;
	private File certFile;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ImportTrustedCertificateAction(KseFrame kseFrame) {
		this(kseFrame, null);
	}

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 * @param trustCert
	 *            Optional certificate; if trustCert is null then user is asked to select a cert via FileDialog
	 */
	public ImportTrustedCertificateAction(KseFrame kseFrame, X509Certificate trustCert) {
		super(kseFrame);
		this.trustCertFromConstructor = trustCert;

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("ImportTrustedCertificateAction.accelerator")
				.charAt(0), Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("ImportTrustedCertificateAction.statusbar"));
		putValue(NAME, res.getString("ImportTrustedCertificateAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ImportTrustedCertificateAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ImportTrustedCertificateAction.image")))));
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

			// handle case that no keystore is currently opened (-> create new keystore)
			if (history == null) {
				new NewAction(kseFrame).actionPerformed(null);
				history = kseFrame.getActiveKeyStoreHistory();

				// cancel pressed => abort
				if (history == null) {
					return;
				}
			}

			KeyStoreState currentState = history.getCurrentState();
			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();

			// use either cert that was passed to c-tor or the one from file selection dialog
			X509Certificate trustCert = null;
			if (trustCertFromConstructor == null) {
				trustCert = showFileSelectionDialog();
				if (trustCert == null) {
					return;
				}
			} else {
				trustCert = trustCertFromConstructor;
			}

			if (applicationSettings.getEnableImportTrustedCertTrustCheck()) {
				String matchAlias = X509CertUtil.matchCertificate(keyStore, trustCert);
				if (matchAlias != null) {
					int selected = JOptionPane.showConfirmDialog(frame,
							MessageFormat.format(
									res.getString("ImportTrustedCertificateAction.TrustCertExistsConfirm.message"),
									matchAlias), res.getString("ImportTrustedCertificateAction.ImportTrustCert.Title"),
							JOptionPane.YES_NO_OPTION);
					if (selected != JOptionPane.YES_OPTION) {
						return;
					}
				}

				KeyStore caCertificates = getCaCertificates();
				KeyStore windowsTrustedRootCertificates = getWindowsTrustedRootCertificates();

				// Establish against current KeyStore
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

				// Can we establish trust for the certificate?
				if (X509CertUtil.establishTrust(trustCert, compKeyStores.toArray(new KeyStore[compKeyStores.size()])) == null) {

					// if trustCert comes from an Examination Dialog (i.e. certFile == null)
					// there is no need to present it again to the user
					if (certFile != null) {

						// display the certificate to the user for confirmation
						JOptionPane.showMessageDialog(frame,
								res.getString("ImportTrustedCertificateAction.NoTrustPathCertConfirm.message"),
								res.getString("ImportTrustedCertificateAction.ImportTrustCert.Title"),
								JOptionPane.INFORMATION_MESSAGE);

						DViewCertificate dViewCertificate = new DViewCertificate(frame, MessageFormat.format(
								res.getString("ImportTrustedCertificateAction.CertDetailsFile.Title"),
								certFile.getName()),
								new X509Certificate[] { trustCert }, null, DViewCertificate.NONE);
						dViewCertificate.setLocationRelativeTo(frame);
						dViewCertificate.setVisible(true);
					}

					int selected = JOptionPane.showConfirmDialog(frame,
							res.getString("ImportTrustedCertificateAction.AcceptTrustCert.message"),
							res.getString("ImportTrustedCertificateAction.ImportTrustCert.Title"),
							JOptionPane.YES_NO_OPTION);

					if (selected != JOptionPane.YES_OPTION) {
						return;
					}
				}
			}

			DGetAlias dGetAlias = new DGetAlias(frame,
					res.getString("ImportTrustedCertificateAction.TrustCertEntryAlias.Title"),
					X509CertUtil.getCertificateAlias(trustCert));
			dGetAlias.setLocationRelativeTo(frame);
			dGetAlias.setVisible(true);
			String alias = dGetAlias.getAlias();

			if (alias == null) {
				return;
			}

			if (keyStore.containsAlias(alias)) {
				String message = MessageFormat.format(
						res.getString("ImportTrustedCertificateAction.OverWriteEntry.message"), alias);

				int selected = JOptionPane.showConfirmDialog(frame, message,
						res.getString("ImportTrustedCertificateAction.ImportTrustCert.Title"),
						JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}

				keyStore.deleteEntry(alias);
				newState.removeEntryPassword(alias);
			}

			keyStore.setCertificateEntry(alias, trustCert);

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane.showMessageDialog(frame,
					res.getString("ImportTrustedCertificateAction.ImportTrustCertSuccessful.message"),
					res.getString("ImportTrustedCertificateAction.ImportTrustCert.Title"),
					JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private X509Certificate showFileSelectionDialog() {
		certFile = chooseTrustedCertificateFile();
		if (certFile == null) {
			return null;
		}

		X509Certificate[] certs = openCertificate(certFile);

		if ((certs == null) || (certs.length == 0)) {
			return null;
		}

		if (certs.length > 1) {
			JOptionPane.showMessageDialog(frame,
					res.getString("ImportTrustedCertificateAction.NoMultipleTrustCertImport.message"),
					res.getString("ImportTrustedCertificateAction.ImportTrustCert.Title"),
					JOptionPane.WARNING_MESSAGE);
			return null;
		}

		return certs[0];
	}

	private File chooseTrustedCertificateFile() {
		JFileChooser chooser = FileChooserFactory.getX509FileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("ImportTrustedCertificateAction.ImportTrustCert.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser
				.showDialog(frame, res.getString("ImportTrustedCertificateAction.ImportTrustCert.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File importFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(importFile);
			return importFile;
		}
		return null;
	}
}
