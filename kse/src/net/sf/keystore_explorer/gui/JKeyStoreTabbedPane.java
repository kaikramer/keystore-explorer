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

package net.sf.keystore_explorer.gui;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetEvent;
import java.awt.dnd.DropTargetListener;
import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.swing.JTabbedPane;

import net.sf.keystore_explorer.gui.actions.OpenAction;
import net.sf.keystore_explorer.gui.error.DError;

/**
 * Drop target for opening KeyStore files.
 * 
 */
public class JKeyStoreTabbedPane extends JTabbedPane implements DropTargetListener {
	private KseFrame kseFrame;

	/**
	 * Construct KeyStore tabbed pane.
	 * 
	 * @param kseFrame
	 *            KSE frame
	 */
	public JKeyStoreTabbedPane(KseFrame kseFrame) {
		this.kseFrame = kseFrame;

		// Make this pane a drop target and its own listener
		new DropTarget(this, this);
	}

	public void drop(DropTargetDropEvent evt) {
		try {
			evt.acceptDrop(DnDConstants.ACTION_MOVE);

			Transferable trans = evt.getTransferable();

			if (trans.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
				List droppedFiles = (List) trans.getTransferData(DataFlavor.javaFileListFlavor);

				OpenAction openAction = new OpenAction(kseFrame);

				for (int i = 0; i < droppedFiles.size(); i++) {
					File droppedFile = (File) droppedFiles.get(i);
					openAction.openKeyStore(droppedFile);
				}
			}
		} catch (IOException ex) {
			DError.displayError(kseFrame.getUnderlyingFrame(), ex);
		} catch (UnsupportedFlavorException ex) {
			DError.displayError(kseFrame.getUnderlyingFrame(), ex);
		}
	}

	public void dragEnter(DropTargetDragEvent evt) {
	}

	public void dragExit(DropTargetEvent evt) {
	}

	public void dragOver(DropTargetDragEvent evt) {
	}

	public void dropActionChanged(DropTargetDragEvent evt) {
	}
}
