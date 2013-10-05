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

import java.awt.Toolkit;
import java.io.File;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.KeyStroke;

import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DViewCertificate;
import net.sf.keystore_explorer.gui.error.DError;

/**
 * Action to examine a certificate.
 * 
 */
public class ExamineCertificateAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 * 
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExamineCertificateAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("ExamineCertificateAction.accelerator")
				.charAt(0), Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("ExamineCertificateAction.statusbar"));
		putValue(NAME, res.getString("ExamineCertificateAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExamineCertificateAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ExamineCertificateAction.image")))));
	}

	/**
	 * Do action.
	 */
	protected void doAction() {
		File certificateFile = chooseCertificateFile(kseFrame);

		if (certificateFile == null) {
			return;
		}

		try {
			X509Certificate[] certs = openCertificate(certificateFile);

			if ((certs != null) && (certs.length > 0)) {
				DViewCertificate dViewCertificate = new DViewCertificate(frame, MessageFormat.format(
						res.getString("ExamineCertificateAction.CertDetailsFile.Title"), certificateFile.getName()),
						certs, kseFrame, DViewCertificate.IMPORT);
				dViewCertificate.setLocationRelativeTo(frame);
				dViewCertificate.setVisible(true);
				return;
			}
		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return;
		}
	}

	private File chooseCertificateFile(KseFrame kseFrame) {
		JFileChooser chooser = FileChooserFactory.getCertFileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("ExamineCertificateAction.ExamineCertificate.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(frame, res.getString("ExamineCertificateAction.ExamineCertificate.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File openFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(openFile);
			return openFile;
		}
		return null;
	}
}
