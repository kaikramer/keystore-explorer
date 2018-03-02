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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.Password;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.MidletSigner;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.sign.DSignMidlet;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to sign a MIDlet using the selected key pair entry.
 *
 */
public class SignMidletAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public SignMidletAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("SignMidletAction.statusbar"));
		putValue(NAME, res.getString("SignMidletAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SignMidletAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("SignMidletAction.image")))));
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

			KeyStore keyStore = currentState.getKeyStore();

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			X509Certificate[] certs = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore
					.getCertificateChain(alias)));

			if (!privateKey.getAlgorithm().equals(KeyPairType.RSA.jce())) {
				JOptionPane.showMessageDialog(frame,
						res.getString("SignMidletAction.ReqRsaKeyPairMidletSigning.message"),
						res.getString("SignMidletAction.SignMidlet.Title"), JOptionPane.WARNING_MESSAGE);
				return;
			}

			DSignMidlet dSignMidlet = new DSignMidlet(frame);
			dSignMidlet.setLocationRelativeTo(frame);
			dSignMidlet.setVisible(true);

			File inputJadFile = dSignMidlet.getInputJad();
			File outputJadFile = dSignMidlet.getOutputJad();
			File jarFile = dSignMidlet.getJar();

			if (inputJadFile == null) {
				return;
			}

			if (inputJadFile.equals(outputJadFile)) {
				MidletSigner.sign(inputJadFile, jarFile, (RSAPrivateKey) privateKey, certs, 1);
			} else {
				MidletSigner.sign(inputJadFile, outputJadFile, jarFile, (RSAPrivateKey) privateKey, certs, 1);
			}

			JOptionPane.showMessageDialog(frame, res.getString("SignMidletAction.SignMidletSuccessful.message"),
					res.getString("SignMidletAction.SignMidlet.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
