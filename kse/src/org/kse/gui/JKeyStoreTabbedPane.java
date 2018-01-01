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

package org.kse.gui;

import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetEvent;
import java.awt.dnd.DropTargetListener;

import javax.swing.JTabbedPane;

import org.kse.gui.dnd.DroppedFileHandler;

/**
 * Drop target for opening KeyStore files.
 *
 */
public class JKeyStoreTabbedPane extends JTabbedPane implements DropTargetListener {
	private static final long serialVersionUID = 1L;
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

	@Override
	public void drop(DropTargetDropEvent evt) {
		DroppedFileHandler.drop(evt, kseFrame);
	}

	@Override
	public void dragEnter(DropTargetDragEvent evt) {
	}

	@Override
	public void dragExit(DropTargetEvent evt) {
	}

	@Override
	public void dragOver(DropTargetDragEvent evt) {
	}

	@Override
	public void dropActionChanged(DropTargetDragEvent evt) {
	}
}
