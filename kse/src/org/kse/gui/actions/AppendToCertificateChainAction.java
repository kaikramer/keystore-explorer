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
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.kse.crypto.Password;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to append to the selected key pair entry's certificate chain.
 *
 */
public class AppendToCertificateChainAction extends KeyStoreExplorerAction implements HistoryAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public AppendToCertificateChainAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("AppendToCertificateChainAction.statusbar"));
		putValue(NAME, res.getString("AppendToCertificateChainAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("AppendToCertificateChainAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("AppendToCertificateChainAction.image")))));
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

			Key privKey = keyStore.getKey(alias, password.toCharArray());

			X509Certificate[] certChain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore
					.getCertificateChain(alias)));

			// Certificate to append to is the end one in the chain
			X509Certificate certToAppendTo = certChain[certChain.length - 1];

			if (X509CertUtil.isCertificateSelfSigned(certToAppendTo)) {
				JOptionPane.showMessageDialog(frame,
						res.getString("AppendToCertificateChainAction.CannotAppendCertSelfSigned.message"),
						res.getString("AppendToCertificateChainAction.AppendToCertificateChain.Title"),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			File certFile = chooseAppendCertificateFile();
			if (certFile == null) {
				return;
			}

			X509Certificate[] certs = openCertificate(certFile);

			if ((certs == null) || (certs.length == 0)) {
				return;
			}

			if (certs.length > 1) {
				JOptionPane.showMessageDialog(frame,
						res.getString("AppendToCertificateChainAction.NoMultipleAppendCert.message"),
						res.getString("AppendToCertificateChainAction.AppendToCertificateChain.Title"),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			X509Certificate certToAppend = certs[0];

			if (!X509CertUtil.verifyCertificate(certToAppendTo, certToAppend)) {
				JOptionPane.showMessageDialog(frame,
						res.getString("AppendToCertificateChainAction.AppendCertNotSigner.message"),
						res.getString("AppendToCertificateChainAction.AppendToCertificateChain.Title"),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			X509Certificate[] newCertChain = new X509Certificate[certChain.length + 1];

			System.arraycopy(certChain, 0, newCertChain, 0, certChain.length);
			newCertChain[newCertChain.length - 1] = certToAppend;

			keyStore.deleteEntry(alias);

			keyStore.setKeyEntry(alias, privKey, password.toCharArray(), newCertChain);

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane.showMessageDialog(frame,
					res.getString("AppendToCertificateChainAction.AppendToCertificateChainSuccessful.message"),
					res.getString("AppendToCertificateChainAction.AppendToCertificateChain.Title"),
					JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private File chooseAppendCertificateFile() {
		JFileChooser chooser = FileChooserFactory.getX509FileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("AppendToCertificateChainAction.AppendToCertificateChain.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(frame,
				res.getString("AppendToCertificateChainAction.AppendCertificate.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File openFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(openFile);
			return openFile;
		}
		return null;
	}
}
