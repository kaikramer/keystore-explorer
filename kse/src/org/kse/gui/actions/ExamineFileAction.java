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
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.apache.commons.io.FileUtils;
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
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
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
public class ExamineFileAction extends KeyStoreExplorerAction {

	private static final long serialVersionUID = -6806220856996693050L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExamineFileAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("ExamineFileAction.accelerator")
				.charAt(0), Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("ExamineFileAction.statusbar"));
		putValue(NAME, res.getString("ExamineFileAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExamineFileAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource("images/examinefile.png"))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		File file = chooseFile();
		openFile(file);
	}

	public void openFile(File file) {
		if (file == null) {
			return;
		}

		try {
			// detect file type and use the right action class for opening the file
			CryptoFileType fileType = CryptoFileUtil.detectFileType(file);

			switch (fileType) {
			case JCEKS_KS:
			case JKS_KS:
			case PKCS12_KS:
			case BKS_KS:
			case BKS_V1_KS:
			case BCFKS_KS:
			case UBER_KS:
				OpenAction openAction = new OpenAction(kseFrame);
				openAction.openKeyStore(file);
				break;
			case CERT:
				openCert(file);
				break;
			case CRL:
				openCrl(file);
				break;
			case PKCS10_CSR:
			case SPKAC_CSR:
				openCsr(file, fileType);
				break;
			case ENC_PKCS8_PVK:
			case UNENC_PKCS8_PVK:
			case ENC_OPENSSL_PVK:
			case UNENC_OPENSSL_PVK:
			case ENC_MS_PVK:
			case UNENC_MS_PVK:
				openPrivateKey(file, fileType);
				break;
			case OPENSSL_PUB:
				openPublicKey(file);
				break;
			case UNKNOWN:
			default:
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("ExamineFileAction.UnknownFileType.message"), file),
						res.getString("ExamineFileAction.ExamineFile.Title"), JOptionPane.WARNING_MESSAGE);
				break;
			}
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("ExamineFileAction.NotFile.message"), file),
					res.getString("ExamineFileAction.ExamineFile.Title"), JOptionPane.WARNING_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private void openCert(File file) throws CryptoException {
		X509Certificate[] certs = openCertificate(file);

		if ((certs != null) && (certs.length > 0)) {
			DViewCertificate dViewCertificate = new DViewCertificate(frame, MessageFormat.format(
					res.getString("ExamineFileAction.CertDetailsFile.Title"), file.getName()),
					certs, kseFrame, DViewCertificate.IMPORT_EXPORT);
			dViewCertificate.setLocationRelativeTo(frame);
			dViewCertificate.setVisible(true);
		}
	}

	private void openCrl(File file) {
		if (file == null) {
			return;
		}

		X509CRL crl = null;
		try {
			byte[] data = FileUtils.readFileToByteArray(file);
			crl = X509CertUtil.loadCRL(data);
		} catch (Exception ex) {
			String problemStr = MessageFormat.format(res.getString("ExamineFileAction.NoOpenCrl.Problem"),
					file.getName());

			String[] causes = new String[] { res.getString("ExamineFileAction.NotCrl.Cause"),
					res.getString("ExamineFileAction.CorruptedCrl.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(frame, res.getString("ExamineFileAction.ProblemOpeningCrl.Title"),
					problem);
			dProblem.setLocationRelativeTo(frame);
			dProblem.setVisible(true);
		}

		if (crl != null) {
			DViewCrl dViewCrl = new DViewCrl(frame, MessageFormat.format(
					res.getString("ExamineFileAction.CrlDetailsFile.Title"), file.getName()), crl);
			dViewCrl.setLocationRelativeTo(frame);
			dViewCrl.setVisible(true);
		}
	}

	private void openCsr(File file, CryptoFileType fileType) throws CryptoException {
		if (file == null) {
			return;
		}

		PKCS10CertificationRequest pkcs10Csr = null;
		Spkac spkacCsr = null;

		try {
			byte[] data = FileUtils.readFileToByteArray(file);
			if (fileType == CryptoFileType.PKCS10_CSR) {
				pkcs10Csr = Pkcs10Util.loadCsr(data);
			} else if (fileType == CryptoFileType.SPKAC_CSR) {
				spkacCsr = new Spkac(data);
			}
		} catch (Exception ex) {
			String problemStr = MessageFormat.format(res.getString("ExamineFileAction.NoOpenCsr.Problem"),
					file.getName());

			String[] causes = new String[] { res.getString("ExamineFileAction.NotCsr.Cause"),
					res.getString("ExamineFileAction.CorruptedCsr.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(frame, res.getString("ExamineFileAction.ProblemOpeningCsr.Title"),
					problem);
			dProblem.setLocationRelativeTo(frame);
			dProblem.setVisible(true);

			return;
		}

		if (pkcs10Csr != null) {
			DViewCsr dViewCsr = new DViewCsr(frame, MessageFormat.format(
					res.getString("ExamineFileAction.CsrDetailsFile.Title"), file.getName()), pkcs10Csr);
			dViewCsr.setLocationRelativeTo(frame);
			dViewCsr.setVisible(true);
		} else {
			DViewCsr dViewCsr = new DViewCsr(frame, MessageFormat.format(
					res.getString("ExamineFileAction.CsrDetailsFile.Title"), file.getName()), spkacCsr);
			dViewCsr.setLocationRelativeTo(frame);
			dViewCsr.setVisible(true);
		}
	}

	private void openPrivateKey(File file, CryptoFileType fileType) throws IOException, CryptoException {

		byte[] data = FileUtils.readFileToByteArray(file);
		PrivateKey privKey = null;
		Password password = null;

		switch (fileType) {
		case ENC_PKCS8_PVK:
			password = getPassword(file);
			if (password == null || password.isNulled()) {
				return;
			}
			privKey = Pkcs8Util.loadEncrypted(data, password);
			break;
		case UNENC_PKCS8_PVK:
			privKey = Pkcs8Util.load(data);
			break;
		case ENC_OPENSSL_PVK:
			password = getPassword(file);
			if (password == null || password.isNulled()) {
				return;
			}
			privKey = OpenSslPvkUtil.loadEncrypted(data, password);
			break;
		case UNENC_OPENSSL_PVK:
			privKey = OpenSslPvkUtil.load(data);
			break;
		case ENC_MS_PVK:
			password = getPassword(file);
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

		DViewPrivateKey dViewPrivateKey = new DViewPrivateKey(frame, MessageFormat.format(
				res.getString("ExamineFileAction.PrivateKeyDetailsFile.Title"), file.getName()), privKey);
		dViewPrivateKey.setLocationRelativeTo(frame);
		dViewPrivateKey.setVisible(true);
	}

	private void openPublicKey(File file) throws IOException, CryptoException {
		byte[] data = FileUtils.readFileToByteArray(file);
		PublicKey publicKey = OpenSslPubUtil.load(data);

		DViewPublicKey dViewPublicKey = new DViewPublicKey(frame, MessageFormat.format(
				res.getString("ExamineFileAction.PublicKeyDetailsFile.Title"), file.getName()), publicKey);
		dViewPublicKey.setLocationRelativeTo(frame);
		dViewPublicKey.setVisible(true);
	}

	private Password getPassword(File file) {
		DGetPassword dGetPassword = new DGetPassword(frame, MessageFormat.format(
				res.getString("ExamineFileAction.EnterPassword.Title"), file.getName()));
		dGetPassword.setLocationRelativeTo(frame);
		dGetPassword.setVisible(true);
		return dGetPassword.getPassword();
	}

	private File chooseFile() {
		JFileChooser chooser = FileChooserFactory.getCertFileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("ExamineFileAction.ExamineFile.Title"));
		chooser.setMultiSelectionEnabled(false);
		chooser.setApproveButtonText(res.getString("ExamineFileAction.ExamineFile.button"));

		int rtnValue = chooser.showOpenDialog(frame);
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File openFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(openFile);
			return openFile;
		}
		return null;
	}
}
