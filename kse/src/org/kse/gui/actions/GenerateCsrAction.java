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
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.csr.CsrType;
import org.kse.crypto.csr.pkcs10.Pkcs10Util;
import org.kse.crypto.csr.spkac.Spkac;
import org.kse.crypto.csr.spkac.SpkacSubject;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DGenerateCsr;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;
import org.kse.utilities.io.IOUtils;

/**
 * Action to generate a CSR using the selected key pair entry.
 *
 */
public class GenerateCsrAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

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
	@Override
	protected void doAction() {
		File csrFile = null;
		FileOutputStream fos = null;

		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();
			Provider provider = history.getExplicitProvider();

			String alias = kseFrame.getSelectedEntryAlias();

			Password password = getEntryPassword(alias, currentState);

			if (password == null) {
				return;
			}

			KeyStore keyStore = currentState.getKeyStore();

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

			String keyPairAlg = privateKey.getAlgorithm();
			KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);

			if (keyPairType == null) {
				throw new CryptoException(MessageFormat.format(
						res.getString("GenerateCsrAction.NoCsrForKeyPairAlg.message"), keyPairAlg));
			}

			// determine dir of current keystore as proposal for CSR file location
			String path = CurrentDirectory.get().getAbsolutePath();
			File keyStoreFile = history.getFile();
			if (keyStoreFile != null) {
				path = keyStoreFile.getAbsoluteFile().getParent();
			}

			DGenerateCsr dGenerateCsr = new DGenerateCsr(frame, alias, privateKey, keyPairType, path, provider);
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
			IOUtils.closeQuietly(fos);
		}

		JOptionPane.showMessageDialog(frame, res.getString("GenerateCsrAction.CsrGenerationSuccessful.message"),
				res.getString("GenerateCsrAction.GenerateCsr.Title"), JOptionPane.INFORMATION_MESSAGE);
	}
}
