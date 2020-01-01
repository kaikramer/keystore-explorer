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
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.csr.pkcs10.Pkcs10Util;
import org.kse.crypto.csr.spkac.Spkac;
import org.kse.crypto.filetype.CryptoFileType;
import org.kse.crypto.filetype.CryptoFileUtil;
import org.kse.crypto.privatekey.MsPvkUtil;
import org.kse.crypto.privatekey.OpenSslPvkUtil;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.crypto.publickey.OpenSslPubUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewCertificate;
import org.kse.gui.dialogs.DViewCrl;
import org.kse.gui.dialogs.DViewCsr;
import org.kse.gui.dialogs.DViewPrivateKey;
import org.kse.gui.dialogs.DViewPublicKey;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.gui.password.DGetPassword;

/**
 * Action to examine a certificate.
 *
 */
public class ExamineClipboardAction extends KeyStoreExplorerAction {

	private static final long serialVersionUID = -4374420674229658652L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExamineClipboardAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("ExamineClipboardAction.accelerator")
				.charAt(0), Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("ExamineClipboardAction.statusbar"));
		putValue(NAME, res.getString("ExamineClipboardAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExamineClipboardAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource("images/examineclipboard.png"))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

		// get clipboard contents, but only string types, not files
		Transferable t = clipboard.getContents(null);
		try {
			if (t.isDataFlavorSupported(DataFlavor.stringFlavor)) {
				String data;
				data = (String) t.getTransferData(DataFlavor.stringFlavor);
				show(data);
			}

			// TODO handle other flavor types

		} catch (UnsupportedFlavorException e) {
			// ignore
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Show clipboard content
	 *
	 * @param data
	 */
	public void show(String data) {

		if (data == null) {
			return;
		}

		try {

			CryptoFileType fileType = CryptoFileUtil.detectFileType(data.getBytes());

			switch (fileType) {
			case CERT:
				showCert(data.getBytes());
				break;
			case CRL:
				showCrl(data.getBytes());
				break;
			case PKCS10_CSR:
			case SPKAC_CSR:
				showCsr(data.getBytes(), fileType);
				break;
			case ENC_PKCS8_PVK:
			case UNENC_PKCS8_PVK:
			case ENC_OPENSSL_PVK:
			case UNENC_OPENSSL_PVK:
			case ENC_MS_PVK:
			case UNENC_MS_PVK:
				showPrivateKey(data.getBytes(), fileType);
				break;
			case OPENSSL_PUB:
				showPublicKey(data.getBytes());
				break;
			case JCEKS_KS:
			case JKS_KS:
			case PKCS12_KS:
			case BKS_KS:
			case BKS_V1_KS:
			case UBER_KS:
			case BCFKS_KS:
			case UNKNOWN:
			default:
				JOptionPane.showMessageDialog(frame,
						res.getString("ExamineClipboardAction.UnknownType.message"),
						res.getString("ExamineClipboardAction.ExamineClipboard.Title"), JOptionPane.WARNING_MESSAGE);
				break;
			}

		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private void showPrivateKey(byte[] data, CryptoFileType fileType) throws IOException, CryptoException {
		PrivateKey privKey = null;
		Password password = null;

		switch (fileType) {
		case ENC_PKCS8_PVK:
			password = getPassword();
			if (password == null || password.isNulled()) {
				return;
			}
			privKey = Pkcs8Util.loadEncrypted(data, password);
			break;
		case UNENC_PKCS8_PVK:
			privKey = Pkcs8Util.load(data);
			break;
		case ENC_OPENSSL_PVK:
			password = getPassword();
			if (password == null || password.isNulled()) {
				return;
			}
			privKey = OpenSslPvkUtil.loadEncrypted(data, password);
			break;
		case UNENC_OPENSSL_PVK:
			privKey = OpenSslPvkUtil.load(data);
			break;
		case ENC_MS_PVK:
			password = getPassword();
			if (password == null || password.isNulled()) {
				return;
			}
			privKey = MsPvkUtil.loadEncrypted(data, password);
			break;
		case UNENC_MS_PVK:
			privKey = MsPvkUtil.load(data);
			break;
		default:
			break;
		}

		DViewPrivateKey dViewPrivateKey = new DViewPrivateKey(frame,
				res.getString("ExamineClipboardAction.PrivateKeyDetails.Title"), privKey);
		dViewPrivateKey.setLocationRelativeTo(frame);
		dViewPrivateKey.setVisible(true);
	}

	private Password getPassword() {
		DGetPassword dGetPassword = new DGetPassword(frame,
				res.getString("ExamineClipboardAction.EnterPassword.Title"));
		dGetPassword.setLocationRelativeTo(frame);
		dGetPassword.setVisible(true);
		return dGetPassword.getPassword();
	}

	private void showPublicKey(byte[] data) throws IOException, CryptoException {
		PublicKey publicKey = OpenSslPubUtil.load(data);

		DViewPublicKey dViewPublicKey = new DViewPublicKey(frame,
				res.getString("ExamineClipboardAction.PublicKeyDetails.Title"), publicKey);
		dViewPublicKey.setLocationRelativeTo(frame);
		dViewPublicKey.setVisible(true);
	}

	private void showCert(byte[] data) throws CryptoException {

		X509Certificate[] certs = null;
		try {
			certs = X509CertUtil.loadCertificates(data);

			if (certs.length == 0) {
				JOptionPane.showMessageDialog(frame,
						res.getString("ExamineClipboardAction.NoCertsFound.message"),
						res.getString("ExamineClipboardAction.OpenCertificate.Title"), JOptionPane.WARNING_MESSAGE);
			}
		} catch (Exception ex) {
			String problemStr = res.getString("ExamineClipboardAction.NoOpenCert.Problem");

			String[] causes = new String[] { res.getString("ExamineClipboardAction.NotCert.Cause"),
					res.getString("ExamineClipboardAction.CorruptedCert.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(frame, res.getString("ExamineClipboardAction.ProblemOpeningCert.Title"),
					problem);
			dProblem.setLocationRelativeTo(frame);
			dProblem.setVisible(true);
		}

		if (certs != null && certs.length > 0) {
			DViewCertificate dViewCertificate = new DViewCertificate(frame,
					res.getString("ExamineClipboardAction.CertDetails.Title"), certs, kseFrame, DViewCertificate.IMPORT_EXPORT);
			dViewCertificate.setLocationRelativeTo(frame);
			dViewCertificate.setVisible(true);
		}
	}

	private void showCrl(byte[] data) {
		if (data == null) {
			return;
		}

		X509CRL crl = null;
		try {
			crl = X509CertUtil.loadCRL(data);
		} catch (Exception ex) {
			String problemStr = res.getString("ExamineClipboardAction.NoOpenCrl.Problem");

			String[] causes = new String[] { res.getString("ExamineClipboardAction.NotCrl.Cause"),
					res.getString("ExamineClipboardAction.CorruptedCrl.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(frame, res.getString("ExamineClipboardAction.ProblemOpeningCrl.Title"),
					problem);
			dProblem.setLocationRelativeTo(frame);
			dProblem.setVisible(true);
		}

		if (crl != null) {
			DViewCrl dViewCrl = new DViewCrl(frame, res.getString("ExamineClipboardAction.CrlDetails.Title"), crl);
			dViewCrl.setLocationRelativeTo(frame);
			dViewCrl.setVisible(true);
		}
	}


	private void showCsr(byte[] data, CryptoFileType fileType) {
		if (data == null) {
			return;
		}

		try {
			PKCS10CertificationRequest pkcs10Csr = null;
			Spkac spkacCsr = null;

			try {
				if (fileType == CryptoFileType.PKCS10_CSR) {
					pkcs10Csr = Pkcs10Util.loadCsr(data);
				} else if (fileType == CryptoFileType.SPKAC_CSR) {
					spkacCsr = new Spkac(data);
				}
			} catch (Exception ex) {
				String problemStr = res.getString("ExamineClipboardAction.NoOpenCsr.Problem");

				String[] causes = new String[] { res.getString("ExamineClipboardAction.NotCsr.Cause"),
						res.getString("ExamineClipboardAction.CorruptedCsr.Cause") };

				Problem problem = new Problem(problemStr, causes, ex);

				DProblem dProblem = new DProblem(frame, res.getString("ExamineClipboardAction.ProblemOpeningCsr.Title"),
						problem);
				dProblem.setLocationRelativeTo(frame);
				dProblem.setVisible(true);

				return;
			}

			if (pkcs10Csr != null) {
				DViewCsr dViewCsr = new DViewCsr(frame, res.getString("ExamineClipboardAction.CsrDetails.Title"),
						pkcs10Csr);
				dViewCsr.setLocationRelativeTo(frame);
				dViewCsr.setVisible(true);
			} else {
				DViewCsr dViewCsr = new DViewCsr(frame, res.getString("ExamineClipboardAction.CsrDetails.Title"),
						spkacCsr);
				dViewCsr.setLocationRelativeTo(frame);
				dViewCsr.setVisible(true);
			}
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
