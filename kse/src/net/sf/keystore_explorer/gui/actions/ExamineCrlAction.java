/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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

import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;

import java.awt.Toolkit;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.X509CRL;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import net.sf.keystore_explorer.crypto.x509.X509CertUtil;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DViewCrl;
import net.sf.keystore_explorer.gui.error.DProblem;
import net.sf.keystore_explorer.gui.error.Problem;

/**
 * Action to examine a CRL.
 *
 */
public class ExamineCrlAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExamineCrlAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("ExamineCrlAction.accelerator").charAt(0),
				Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("ExamineCrlAction.statusbar"));
		putValue(NAME, res.getString("ExamineCrlAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExamineCrlAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ExamineCrlAction.image")))));
	}

	/**
	 * Do action.
	 */
	protected void doAction() {
		File crlFile = chooseCRLFile();
		openCrl(crlFile);
	}

	private File chooseCRLFile() {
		JFileChooser chooser = FileChooserFactory.getCrlFileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("ExamineCrlAction.ExamineCrl.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(frame, res.getString("ExamineCrlAction.ExamineCrl.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File openFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(openFile);
			return openFile;
		}
		return null;
	}

	/**
	 * Open CRL file.
	 *
	 * @param crlFile
	 */
	public void openCrl(File crlFile) {

       if (crlFile == null) {
            return;
        }

        X509CRL crl = null;
        try {
            crl = X509CertUtil.loadCRL(new FileInputStream(crlFile));
        } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(frame,
                    MessageFormat.format(res.getString("ExamineCrlAction.NoReadFile.message"), crlFile),
                    res.getString("ExamineCrlAction.OpenCrl.Title"), JOptionPane.WARNING_MESSAGE);
        } catch (Exception ex) {
            String problemStr = MessageFormat.format(res.getString("ExamineCrlAction.NoOpenCrl.Problem"),
                    crlFile.getName());

            String[] causes = new String[] { res.getString("ExamineCrlAction.NotCrl.Cause"),
                    res.getString("ExamineCrlAction.CorruptedCrl.Cause") };

            Problem problem = new Problem(problemStr, causes, ex);

            DProblem dProblem = new DProblem(frame, res.getString("ExamineCrlAction.ProblemOpeningCrl.Title"),
                    APPLICATION_MODAL, problem);
            dProblem.setLocationRelativeTo(frame);
            dProblem.setVisible(true);
        }

        if (crl != null) {
            DViewCrl dViewCrl = new DViewCrl(frame, MessageFormat.format(
                    res.getString("ExamineCrlAction.CrlDetailsFile.Title"), crlFile.getName()), crl);
            dViewCrl.setLocationRelativeTo(frame);
            dViewCrl.setVisible(true);
        }
	}
}
