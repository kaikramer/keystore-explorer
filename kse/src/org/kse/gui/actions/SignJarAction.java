/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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
import java.util.List;

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
import org.kse.gui.dialogs.sign.DSignJarSigning;
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
						getClass().getResource("images/signjar.png"))));
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
			
			// set the private key
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			
			// set the certificate
			X509Certificate[] certs = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore
					.getCertificateChain(alias)));

			// set the key pair type
			KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);
			
			// set the signer
			String signer = KSE.getFullApplicationName();

			// get the jars, signatures, and time stamp
			DSignJar dSignJar = new DSignJar(frame, privateKey, keyPairType, alias, certs, provider, signer);
			dSignJar.setLocationRelativeTo(frame);
			dSignJar.setVisible(true);
			
			if (!dSignJar.isSuccessful()) {
				return;
			}

			SignatureType signatureType = dSignJar.getSignatureType();
			String signatureName = dSignJar.getSignatureName();
			File[] inputJarFile = dSignJar.getInputJar();
			List<File> outputJarFile = dSignJar.getOutputJar();
			String tsaUrl = dSignJar.getTimestampingServerUrl();
			DigestType digestType = dSignJar.getDigestType();
			
			// start the jar signing process			
			DSignJarSigning dSignJarSigning = new DSignJarSigning(frame, inputJarFile, outputJarFile,
					privateKey, certs, signatureType, signatureName, signer, digestType, tsaUrl, provider);
			dSignJarSigning.setLocationRelativeTo(frame);
			dSignJarSigning.startDSignJarSigning();
			dSignJarSigning.setVisible(true);
			
			if(!dSignJarSigning.isSuccessful()) {
				return;
			}
			
			// check map size for testing place holder until dialog for logging created
			if(dSignJarSigning.getFileExceptions().size() > 0) {
				for (String key : dSignJarSigning.getFileExceptions().keySet()) {
					System.out.println(key + " - " + dSignJarSigning.getFileExceptions().get(key));
					System.out.println();
				}
			}
		/*
			System.out.println("Sig type: " + signatureType);
			System.out.println("Sig name: " + signatureName);
			System.out.println("Input length: " + inputJarFile.length);
			System.out.println("Input length: " + inputJarFile[0].getAbsolutePath());
			System.out.println("Output size: " + outputJarFile.size());
			System.out.println("TSA: " + tsaUrl);
			System.out.println("Digest type: " + digestType);
*/

			JOptionPane.showMessageDialog(frame, res.getString("SignJarAction.SignJarSuccessful.message"),
					res.getString("SignJarAction.SignJar.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
