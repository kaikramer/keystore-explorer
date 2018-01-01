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
import java.security.Provider;
import java.security.cert.X509Certificate;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.KSE;
import org.kse.crypto.Password;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.JarSigner;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.sign.DSignJar;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to sign a JAR using the selected key pair entry.
 *
 */
public class SignJarAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = -8414470251471035085L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public SignJarAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("SignJarAction.statusbar"));
		putValue(NAME, res.getString("SignJarAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SignJarAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("SignJarAction.image")))));
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
			Provider provider = history.getExplicitProvider();

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			X509Certificate[] certs = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore
					.getCertificateChain(alias)));

			KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);

			DSignJar dSignJar = new DSignJar(frame, privateKey, keyPairType, alias, provider);
			dSignJar.setLocationRelativeTo(frame);
			dSignJar.setVisible(true);

			SignatureType signatureType = dSignJar.getSignatureType();
			String signatureName = dSignJar.getSignatureName();
			File inputJarFile = dSignJar.getInputJar();
			File outputJarFile = dSignJar.getOutputJar();
			String tsaUrl = dSignJar.getTimestampingServerUrl();

			if (signatureType == null) {
				return;
			}

			String signer = KSE.getFullApplicationName();

			DigestType digestType = dSignJar.getDigestType();

			if (inputJarFile.equals(outputJarFile)) {
				JarSigner.sign(inputJarFile, privateKey, certs, signatureType, signatureName, signer, digestType,
						tsaUrl, provider);
			} else {
				JarSigner.sign(inputJarFile, outputJarFile, privateKey, certs, signatureType, signatureName, signer,
						digestType, tsaUrl, provider);
			}

			JOptionPane.showMessageDialog(frame, res.getString("SignJarAction.SignJarSuccessful.message"),
					res.getString("SignJarAction.SignJar.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
