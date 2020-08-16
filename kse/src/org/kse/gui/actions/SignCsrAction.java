/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Date;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.kse.crypto.Password;
import org.kse.crypto.csr.pkcs10.Pkcs10Util;
import org.kse.crypto.csr.spkac.Spkac;
import org.kse.crypto.filetype.CryptoFileType;
import org.kse.crypto.filetype.CryptoFileUtil;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.crypto.x509.X509CertificateGenerator;
import org.kse.crypto.x509.X509CertificateVersion;
import org.kse.crypto.x509.X509ExtensionSet;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.sign.DSignCsr;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to sign a CSR using the selected key pair entry.
 *
 */
public class SignCsrAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public SignCsrAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("SignCsrAction.statusbar"));
		putValue(NAME, res.getString("SignCsrAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SignCsrAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource("images/signcsr.png"))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {

		KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
		KeyStoreState currentState = history.getCurrentState();

		String alias = kseFrame.getSelectedEntryAlias();

		Password password = getEntryPassword(alias, currentState);

		if (password == null) {
			return;
		}

		KeyStore keyStore = currentState.getKeyStore();

		DSignCsr dSignCsr = null;
		X509Certificate[] signingChain = null;
		X509Certificate signingCert = null;
		PrivateKey privateKey = null;
		try {
			privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			Certificate[] certs = keyStore.getCertificateChain(alias);
			KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);
			signingChain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));
			signingCert = signingChain[0];

			File csrFile = chooseCsrFile();
			if (csrFile == null) {
				return;
			}

			dSignCsr = createSignDialogFromCsrFile(csrFile, privateKey, keyPairType, signingCert);
			if (dSignCsr == null) {
				return;
			}
			dSignCsr.setLocationRelativeTo(frame);
			dSignCsr.setVisible(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return;
		}

		// Dialog was cancelled...
		if (dSignCsr.getVersion() == null) {
			return;
		}

		generateCaReply(history, dSignCsr, signingChain, signingCert, privateKey);
	}


	private DSignCsr createSignDialogFromCsrFile(File csrFile, PrivateKey privateKey, KeyPairType keyPairType,
			X509Certificate signingCert) {

		try {
			CryptoFileType fileType = CryptoFileUtil.detectFileType(csrFile);
			if (fileType == CryptoFileType.PKCS10_CSR) {
				PKCS10CertificationRequest pkcs10Csr = Pkcs10Util.loadCsr(FileUtils.readFileToByteArray(csrFile));

				if (!Pkcs10Util.verifyCsr(pkcs10Csr)) {
					JOptionPane.showMessageDialog(frame, res.getString("SignCsrAction.NoVerifyPkcs10Csr.message"),
							res.getString("SignCsrAction.SignCsr.Title"), JOptionPane.WARNING_MESSAGE);
					return null;
				}

				return new DSignCsr(frame, pkcs10Csr, csrFile, privateKey, keyPairType, signingCert);
			} else if (fileType == CryptoFileType.SPKAC_CSR) {
				Spkac spkacCsr = new Spkac(FileUtils.readFileToByteArray(csrFile));

				if (!spkacCsr.verify()) {
					JOptionPane.showMessageDialog(frame, res.getString("SignCsrAction.NoVerifySpkacCsr.message"),
							res.getString("SignCsrAction.SignCsr.Title"), JOptionPane.WARNING_MESSAGE);
					return null;
				}

				return new DSignCsr(frame, spkacCsr, csrFile, privateKey, keyPairType, signingCert);
			} else {
				JOptionPane.showMessageDialog(frame, MessageFormat.format(
						res.getString("SignCsrAction.FileNotRecognisedType.message"), csrFile), res
						.getString("SignCsrAction.SignCsr.Title"), JOptionPane.WARNING_MESSAGE);
				return null;
			}

		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("SignCsrAction.NotFile.message"), csrFile),
					res.getString("SignCsrAction.SignCsr.Title"), JOptionPane.WARNING_MESSAGE);
			return null;
		} catch (Exception ex) {
			String problemStr = MessageFormat.format(res.getString("SignCsrAction.NoOpenCsr.Problem"),
					csrFile.getName());

			String[] causes = new String[] { res.getString("SignCsrAction.NotCsr.Cause"),
					res.getString("SignCsrAction.CorruptedCsr.Cause") };

			DProblem dProblem = new DProblem(frame, res.getString("SignCsrAction.ProblemOpeningCsr.Title"),
					new Problem(problemStr, causes, ex));
			dProblem.setLocationRelativeTo(frame);
			dProblem.setVisible(true);

			return null;
		}
	}


	private void generateCaReply(KeyStoreHistory history, DSignCsr dSignCsr, X509Certificate[] signingChain,
			X509Certificate signingCert, PrivateKey privateKey) {

		Provider provider = history.getExplicitProvider();
		X509CertificateVersion version = dSignCsr.getVersion();
		SignatureType signatureType = dSignCsr.getSignatureType();
		Date validityStart = dSignCsr.getValidityStart();
		Date validityEnd = dSignCsr.getValidityEnd();
		BigInteger serialNumber = dSignCsr.getSerialNumber();
		X509ExtensionSet extensions = dSignCsr.getExtensions();
		X500Name subjectDN = dSignCsr.getSubjectDN();
		PublicKey publicKey = dSignCsr.getPublicKey();
		File caReplyFile = dSignCsr.getCaReplyFile();

		try (FileOutputStream fos = new FileOutputStream(caReplyFile)) {

			X500Name issuer = X500NameUtils.x500PrincipalToX500Name(signingCert.getSubjectX500Principal());

			// CA Reply is a cert with subject from CSR and issuer from signing cert's subject
			X509CertificateGenerator generator = new X509CertificateGenerator(version);
			X509Certificate caReplyCert = generator.generate(subjectDN, issuer, validityStart, validityEnd, publicKey,
					privateKey, signatureType, serialNumber, extensions, provider);

			X509Certificate[] caReplyChain = new X509Certificate[signingChain.length + 1];
			caReplyChain[0] = caReplyCert;

			// Add all of the signing chain to the reply
			System.arraycopy(signingChain, 0, caReplyChain, 1, signingChain.length);

			byte[] caCertEncoded = X509CertUtil.getCertsEncodedPkcs7(caReplyChain);

			fos.write(caCertEncoded);

			JOptionPane.showMessageDialog(frame, res.getString("SignCsrAction.SignCsrSuccessful.message"),
					res.getString("SignCsrAction.SignCsr.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("SignJarAction.NoWriteFile.message"), caReplyFile),
					res.getString("SignCsrAction.SignCsr.Title"), JOptionPane.WARNING_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}


	private File chooseCsrFile() {
		JFileChooser chooser = FileChooserFactory.getCsrFileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("SignCsrAction.ChooseCsr.Title"));
		chooser.setMultiSelectionEnabled(false);
		chooser.setApproveButtonText(res.getString("SignCsrAction.ChooseCsr.button"));

		int rtnValue = chooser.showOpenDialog(frame);
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File importFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(importFile);
			return importFile;
		}
		return null;
	}
}
