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
package org.kse.gui.dnd;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.swing.SwingUtilities;

import org.kse.gui.KseFrame;
import org.kse.gui.actions.ExamineFileAction;
import org.kse.gui.error.DError;

public class DroppedFileHandler {

	public static void drop(DropTargetDropEvent evt, final KseFrame kseFrame) {
		evt.acceptDrop(DnDConstants.ACTION_MOVE);
		Transferable trans = evt.getTransferable();

		try {
			if (trans.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {

				@SuppressWarnings("unchecked")
				final List<File> droppedFiles = (List<File>) trans.getTransferData(DataFlavor.javaFileListFlavor);

				// open files in new thread, so we can return quickly
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						openFiles(kseFrame, droppedFiles);
					}
				});

			}
			/*			TODO
				else if (trans.isDataFlavorSupported(DataFlavor.stringFlavor)) {
				String str = trans.getTransferData(DataFlavor.stringFlavor).toString();
				X509Certificate[] certs = X509CertUtil.loadCertificates(IOUtils.toInputStream(str, "UTF-8"));
				if ((certs != null) && (certs.length > 0)) {
					DViewCertificate dViewCertificate = new DViewCertificate(kseFrame.getUnderlyingFrame(),
							MessageFormat.format("Title", ""), certs, kseFrame, DViewCertificate.IMPORT);
					dViewCertificate.setLocationRelativeTo(kseFrame.getUnderlyingFrame());
					dViewCertificate.setVisible(true);
				}
			}
			 */
		} catch (IOException | UnsupportedFlavorException e) {
			DError.displayError(kseFrame.getUnderlyingFrame(), e);
		}
	}

	public static void openFiles(KseFrame kseFrame, List<File> droppedFiles) {

		ExamineFileAction examineFileAction = new ExamineFileAction(kseFrame);

		for (File droppedFile : droppedFiles) {
			try {
				examineFileAction.openFile(droppedFile);
			} catch (Exception e) {
				DError.displayError(kseFrame.getUnderlyingFrame(), e);
			}
		}
	}
}
