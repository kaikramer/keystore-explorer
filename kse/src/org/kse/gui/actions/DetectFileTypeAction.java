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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.filetype.CryptoFileType;
import org.kse.crypto.filetype.CryptoFileUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;

/**
 * Action to detect crypto file type.
 *
 */
public class DetectFileTypeAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public DetectFileTypeAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("DetectFileTypeAction.accelerator").charAt(0),
				Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("DetectFileTypeAction.statusbar"));
		putValue(NAME, res.getString("DetectFileTypeAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("DetectFileTypeAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("DetectFileTypeAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		File detectTypeFile = null;

		try {
			JFileChooser chooser = FileChooserFactory.getCertFileChooser();
			chooser.setCurrentDirectory(CurrentDirectory.get());
			chooser.setDialogTitle(res.getString("ExamineFileAction.ExamineFile.Title"));
			chooser.setMultiSelectionEnabled(false);

			int rtnValue = chooser.showDialog(frame, res.getString("DetectFileTypeAction.DetectFileType.button"));

			if (rtnValue == JFileChooser.APPROVE_OPTION) {
				detectTypeFile = chooser.getSelectedFile();
				CurrentDirectory.updateForFile(detectTypeFile);
			}

			if (detectTypeFile == null) {
				return;
			}

			CryptoFileType fileType = CryptoFileUtil.detectFileType(new FileInputStream(detectTypeFile));

			String message = null;

			if (fileType != null) {
				message = MessageFormat.format(res.getString("DetectFileTypeAction.DetectedFileType.message"),
						detectTypeFile.getName(), fileType.friendly());
			} else {
				StringBuffer sbRecognisedTypes = new StringBuffer();

				for (CryptoFileType type : CryptoFileType.values()) {
					sbRecognisedTypes.append(MessageFormat.format("<li>{0}</li>", type.friendly()));
				}

				message = MessageFormat.format(res.getString("DetectFileTypeAction.NoDetectFileType.message"),
						detectTypeFile.getName(), sbRecognisedTypes.toString());
			}

			JOptionPane.showMessageDialog(frame, message,
					res.getString("DetectFileTypeAction.CryptographicFileType.Title"), JOptionPane.PLAIN_MESSAGE,
					new ImageIcon(getClass().getResource(res.getString("DetectFileTypeAction.DetectFileType.icon"))));
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("DetectFileTypeAction.NoReadFile.message"), detectTypeFile),
					res.getString("DetectFileTypeAction.DetectFileType.Title"), JOptionPane.WARNING_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
