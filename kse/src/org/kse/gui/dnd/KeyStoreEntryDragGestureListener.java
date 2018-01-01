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

import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.dnd.DragGestureEvent;
import java.awt.dnd.DragGestureListener;
import java.awt.dnd.DragSource;
import java.awt.dnd.DragSourceAdapter;
import java.awt.dnd.DragSourceContext;
import java.awt.dnd.DragSourceDragEvent;
import java.awt.image.BufferedImage;

import javax.swing.ImageIcon;

import org.kse.gui.KseFrame;

/**
 * Listens for KeyStore entry drag gestures and starts the drag off if valid.
 *
 */
public class KeyStoreEntryDragGestureListener extends DragSourceAdapter implements DragGestureListener {
	private KseFrame kseFrame;
	private Cursor cursor;

	/**
	 * Construct KeyStoreEntryDragGestureListener.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public KeyStoreEntryDragGestureListener(KseFrame kseFrame) {
		this.kseFrame = kseFrame;
	}

	/**
	 * Drag gesture recognized. Start the drag off if valid.
	 *
	 * @param evt
	 *            Drag gesture event
	 */
	@Override
	public void dragGestureRecognized(DragGestureEvent evt) {
		DragEntry dragEntry = kseFrame.dragSelectedEntry();

		if (dragEntry == null) {
			return;
		}

		ImageIcon icon = dragEntry.getImage();

		// Draw image as drag cursor
		Toolkit toolkit = Toolkit.getDefaultToolkit();
		Dimension dim = toolkit.getBestCursorSize(icon.getIconWidth(), icon.getIconHeight());
		BufferedImage buffImage = new BufferedImage(dim.width, dim.height, BufferedImage.TYPE_INT_ARGB_PRE);
		icon.paintIcon(evt.getComponent(), buffImage.getGraphics(), 0, 0);
		cursor = toolkit.createCustomCursor(buffImage, new Point(0, 0), "keystore-entry");

		evt.startDrag(cursor, new KeyStoreEntryTransferable(dragEntry), this);
	}

	/**
	 * Drag target entered.
	 *
	 * @param evt
	 *            Drag event
	 */
	@Override
	public void dragEnter(DragSourceDragEvent evt) {
		// Show drag cursor
		DragSourceContext ctx = evt.getDragSourceContext();
		ctx.setCursor(cursor);
	}

	/**
	 * Drag target exited.
	 *
	 * @param evt
	 *            Drag event
	 */
	public void dragExit(DragSourceDragEvent evt) {
		// Show no drop cursor
		DragSourceContext ctx = evt.getDragSourceContext();
		ctx.setCursor(DragSource.DefaultCopyNoDrop);
	}
}
