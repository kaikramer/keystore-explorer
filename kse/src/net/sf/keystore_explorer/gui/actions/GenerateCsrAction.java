/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2015 Kai Kramer
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
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.Password;
import net.sf.keystore_explorer.crypto.csr.CsrType;
import net.sf.keystore_explorer.crypto.csr.pkcs10.Pkcs10Util;
import net.sf.keystore_explorer.crypto.csr.spkac.Spkac;
import net.sf.keystore_explorer.crypto.csr.spkac.SpkacSubject;
import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.crypto.signing.SignatureType;
import net.sf.keystore_explorer.crypto.x509.X500NameUtils;
import net.sf.keystore_explorer.crypto.x509.X509CertUtil;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DGenerateCsr;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.history.KeyStoreState;
import net.sf.keystore_explorer.utilities.io.SafeCloseUtil;

/**
 * Action to generate a CSR using the selected key pair entry.
 *
 */
public class GenerateCsrAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public GenerateCsrAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("GenerateCsrAction.statusbar"));
		putValue(NAME, res.getString("GenerateCsrAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("GenerateCsrAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("GenerateCsrAction.image")))));
	}

	/**
	 * Do action.
	 */
	protected void doAction() {
		File csrFile = null;
		FileOutputStream fos = null;

		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			String alias = kseFrame.getSelectedEntryAlias();

			Password password = getEntryPassword(alias, currentState);

			if (password == null) {
				return;
			}

			KeyStore keyStore = currentState.getKeyStore();
			Provider provider = keyStore.getProvider();

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

			String keyPairAlg = privateKey.getAlgorithm();
			KeyPairType keyPairType = null;

			if (privateKey.getAlgorithm().equals(KeyPairType.RSA.jce())) {
				keyPairType = KeyPairType.RSA;
			} else if (privateKey.getAlgorithm().equals(KeyPairType.DSA.jce())) {
				keyPairType = KeyPairType.DSA;
			} else if (privateKey.getAlgorithm().equals(KeyPairType.EC.jce())) {
				keyPairType = KeyPairType.EC;
			} else {
				throw new CryptoException(MessageFormat.format(
						res.getString("GenerateCsrAction.NoCsrForKeyPairAlg.message"), keyPairAlg));
			}

			DGenerateCsr dGenerateCsr = new DGenerateCsr(frame, alias, privateKey, keyPairType, provider);
			dGenerateCsr.setLocationRelativeTo(frame);
			dGenerateCsr.setVisible(true);

			if (!dGenerateCsr.generateSelected()) {
				return;
			}

			CsrType format = dGenerateCsr.getFormat();
			SignatureType signatureType = dGenerateCsr.getSignatureType();
			String challenge = dGenerateCsr.getChallenge();
			String unstructuredName = dGenerateCsr.getUnstructuredName();
			boolean useCertificateExtensions = dGenerateCsr.isAddExtensionsWanted();
			csrFile = dGenerateCsr.getCsrFile();

			X509Certificate firstCertInChain = X509CertUtil.orderX509CertChain(X509CertUtil
					.convertCertificates(keyStore.getCertificateChain(alias)))[0];

			fos = new FileOutputStream(csrFile);

			if (format == CsrType.PKCS10) {
				String csr = Pkcs10Util.getCsrEncodedDerPem(Pkcs10Util.generateCsr(firstCertInChain, privateKey,
						signatureType, challenge, unstructuredName, useCertificateExtensions, provider));

				fos.write(csr.getBytes());
			} else {
				SpkacSubject subject = new SpkacSubject(X500NameUtils.x500PrincipalToX500Name(firstCertInChain
						.getSubjectX500Principal()));
				PublicKey publicKey = firstCertInChain.getPublicKey();

				// TODO handle other providers (PKCS11 etc)
				Spkac spkac = new Spkac(challenge, signatureType, subject, publicKey, privateKey);

				spkac.output(fos);
			}
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("GenerateCsrAction.NoWriteFile.message"), csrFile),
					res.getString("GenerateCsrAction.GenerateCsr.Title"), JOptionPane.WARNING_MESSAGE);
			return;
		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return;
		} finally {
			SafeCloseUtil.close(fos);
		}

		JOptionPane.showMessageDialog(frame, res.getString("GenerateCsrAction.CsrGenerationSuccessful.message"),
				res.getString("GenerateCsrAction.GenerateCsr.Title"), JOptionPane.INFORMATION_MESSAGE);
	}
}
