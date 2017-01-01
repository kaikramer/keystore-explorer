/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.csr.pkcs10.Pkcs10Util;
import net.sf.keystore_explorer.crypto.csr.spkac.Spkac;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileType;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileUtil;
import net.sf.keystore_explorer.crypto.x509.X509CertUtil;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DViewCertificate;
import net.sf.keystore_explorer.gui.dialogs.DViewCrl;
import net.sf.keystore_explorer.gui.dialogs.DViewCsr;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.gui.error.DProblem;
import net.sf.keystore_explorer.gui.error.Problem;


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
						getClass().getResource(res.getString("ExamineFileAction.image")))));
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

		OpenAction openAction = new OpenAction(kseFrame);
		FileInputStream is = null;
		try {

			// detect file type and use the right action class for opening the file
			is = new FileInputStream(file);
			CryptoFileType fileType = CryptoFileUtil.detectFileType(is);

			switch (fileType) {
			case JCEKS_KS:
			case JKS_KS:
			case PKCS12_KS:
			case BKS_KS:
			case BKS_V1_KS:
			case UBER_KS:
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
			case UNKNOWN:
			default:
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("ExamineFileAction.UnknownFileType.message"), file),
						res.getString("ExamineFileAction.ExamineFile.Title"), JOptionPane.WARNING_MESSAGE);
				break;
			}

		} catch (Exception ex) {
			DError.displayError(frame, ex);
		} finally {
			IOUtils.closeQuietly(is);
		}
	}

	private void openCert(File file) throws CryptoException {
		X509Certificate[] certs = openCertificate(file);

		if ((certs != null) && (certs.length > 0)) {
			DViewCertificate dViewCertificate = new DViewCertificate(frame, MessageFormat.format(
					res.getString("ExamineFileAction.CertDetailsFile.Title"), file.getName()),
					certs, kseFrame, DViewCertificate.IMPORT);
			dViewCertificate.setLocationRelativeTo(frame);
			dViewCertificate.setVisible(true);
		}
	}

	private void openCrl(File crlFile) {

		if (crlFile == null) {
			return;
		}

		X509CRL crl = null;
		try {
			crl = X509CertUtil.loadCRL(new FileInputStream(crlFile));
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("ExamineFileAction.NoReadFile.message"), crlFile),
					res.getString("ExamineFileAction.OpenCrl.Title"), JOptionPane.WARNING_MESSAGE);
		} catch (Exception ex) {
			String problemStr = MessageFormat.format(res.getString("ExamineFileAction.NoOpenCrl.Problem"),
					crlFile.getName());

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
					res.getString("ExamineFileAction.CrlDetailsFile.Title"), crlFile.getName()), crl);
			dViewCrl.setLocationRelativeTo(frame);
			dViewCrl.setVisible(true);
		}
	}

	private void openCsr(File csrFile, CryptoFileType fileType) {
		if (csrFile == null) {
			return;
		}

		try {
			PKCS10CertificationRequest pkcs10Csr = null;
			Spkac spkacCsr = null;

			try {
				if (fileType == CryptoFileType.PKCS10_CSR) {
					pkcs10Csr = Pkcs10Util.loadCsr(new FileInputStream(csrFile));
				} else if (fileType == CryptoFileType.SPKAC_CSR) {
					spkacCsr = new Spkac(new FileInputStream(csrFile));
				}
			} catch (FileNotFoundException ex) {
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("ExamineCsrAction.NotFile.message"), csrFile),
						res.getString("ExamineFileAction.ExamineCsr.Title"), JOptionPane.WARNING_MESSAGE);
				return;
			} catch (Exception ex) {
				String problemStr = MessageFormat.format(res.getString("ExamineFileAction.NoOpenCsr.Problem"),
						csrFile.getName());

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
						res.getString("ExamineFileAction.CsrDetailsFile.Title"), csrFile.getName()), pkcs10Csr);
				dViewCsr.setLocationRelativeTo(frame);
				dViewCsr.setVisible(true);
			} else {
				DViewCsr dViewCsr = new DViewCsr(frame, MessageFormat.format(
						res.getString("ExamineFileAction.CsrDetailsFile.Title"), csrFile.getName()), spkacCsr);
				dViewCsr.setLocationRelativeTo(frame);
				dViewCsr.setVisible(true);
			}
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private File chooseFile() {
		JFileChooser chooser = FileChooserFactory.getCertFileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("ExamineFileAction.ExamineFile.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(frame, res.getString("ExamineFileAction.ExamineFile.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File openFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(openFile);
			return openFile;
		}
		return null;
	}
}
