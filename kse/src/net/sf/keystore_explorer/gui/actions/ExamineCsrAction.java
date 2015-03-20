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

import static java.awt.Dialog.ModalityType.DOCUMENT_MODAL;

import java.awt.Toolkit;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import net.sf.keystore_explorer.crypto.csr.pkcs10.Pkcs10Util;
import net.sf.keystore_explorer.crypto.csr.spkac.Spkac;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileType;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileUtil;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DViewCsr;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.gui.error.DProblem;
import net.sf.keystore_explorer.gui.error.Problem;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;


/**
 * Action to examine a CSR.
 *
 */
public class ExamineCsrAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExamineCsrAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("ExamineCsrAction.accelerator").charAt(0),
				Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("ExamineCsrAction.statusbar"));
		putValue(NAME, res.getString("ExamineCsrAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExamineCsrAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ExamineCsrAction.image")))));
	}

	/**
	 * Do action.
	 */
	protected void doAction() {
		File csrFile = chooseCsrFile(kseFrame);
		openCsr(csrFile);
	}

    public void openCsr(File csrFile) {
        if (csrFile == null) {
			return;
		}

		try {
			PKCS10CertificationRequest pkcs10Csr = null;
			Spkac spkacCsr = null;

			try {
				CryptoFileType fileType = CryptoFileUtil.detectFileType(new FileInputStream(csrFile));
				if (fileType == CryptoFileType.PKCS10_CSR) {
					pkcs10Csr = Pkcs10Util.loadCsr(new FileInputStream(csrFile));
				} else if (fileType == CryptoFileType.SPKAC_CSR) {
					spkacCsr = new Spkac(new FileInputStream(csrFile));
				} else {
					JOptionPane.showMessageDialog(frame, MessageFormat.format(
							res.getString("ExamineCsrAction.FileNotRecognisedType.message"), csrFile), res
							.getString("ExamineCsrAction.ExamineCsr.Title"), JOptionPane.WARNING_MESSAGE);
					return;
				}
			} catch (FileNotFoundException ex) {
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("ExamineCsrAction.NotFile.message"), csrFile),
						res.getString("ExamineCsrAction.ExamineCsr.Title"), JOptionPane.WARNING_MESSAGE);
				return;
			} catch (Exception ex) {
				String problemStr = MessageFormat.format(res.getString("ExamineCsrAction.NoOpenCsr.Problem"),
						csrFile.getName());

				String[] causes = new String[] { res.getString("ExamineCsrAction.NotCsr.Cause"),
						res.getString("ExamineCsrAction.CorruptedCsr.Cause") };

				Problem problem = new Problem(problemStr, causes, ex);

				DProblem dProblem = new DProblem(frame, res.getString("ExamineCsrAction.ProblemOpeningCsr.Title"),
						DOCUMENT_MODAL, problem);
				dProblem.setLocationRelativeTo(frame);
				dProblem.setVisible(true);

				return;
			}

			if (pkcs10Csr != null) {
				DViewCsr dViewCsr = new DViewCsr(frame, MessageFormat.format(
						res.getString("ExamineCsrAction.CsrDetailsFile.Title"), csrFile.getName()), pkcs10Csr);
				dViewCsr.setLocationRelativeTo(frame);
				dViewCsr.setVisible(true);
				return;
			} else {
				DViewCsr dViewCsr = new DViewCsr(frame, MessageFormat.format(
						res.getString("ExamineCsrAction.CsrDetailsFile.Title"), csrFile.getName()), spkacCsr);
				dViewCsr.setLocationRelativeTo(frame);
				dViewCsr.setVisible(true);
				return;
			}
		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return;
		}
    }

	private File chooseCsrFile(KseFrame kseFrame) {
		JFileChooser chooser = FileChooserFactory.getCsrFileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("ExamineCsrAction.ExamineCsr.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(frame, res.getString("ExamineCsrAction.ExamineCsr.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File openFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(openFile);
			return openFile;
		}
		return null;
	}
}
