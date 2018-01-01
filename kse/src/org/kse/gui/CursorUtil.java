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

import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.event.MouseAdapter;

import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;

/**
 * Cursor utility methods.
 *
 */
public class CursorUtil {
	private CursorUtil() {
	}

	/**
	 * Set cursor to busy and disable application input. This can be reversed by
	 * a subsequent call to setCursorFree.
	 *
	 * @param frame
	 *            Frame to apply to
	 */
	public static void setCursorBusy(JFrame frame) {
		setCursorBusy(frame.getRootPane().getGlassPane());
	}

	/**
	 * Set cursor to free and enable application input. Called after a call to
	 * setCursorBusy.
	 *
	 * @param frame
	 *            Frame to apply to
	 */
	public static void setCursorFree(JFrame frame) {
		setCursorFree(frame.getRootPane().getGlassPane());
	}

	/**
	 * Set cursor to busy and disable application input. This can be reversed by
	 * a subsequent call to setCursorFree.
	 *
	 * @param component
	 *            Component within container to apply to
	 */
	public static void setCursorBusy(JComponent component) {
		JDialog dialog = findContainingDialog(component);

		if (dialog != null) {
			setCursorBusy(dialog);
		} else {
			JFrame frame = findContainingFrame(component);

			if (frame != null) {
				setCursorBusy(frame);
			}
		}
	}

	/**
	 * Set cursor to free and enable application input. Called after a call to
	 * setCursorBusy.
	 *
	 * @param component
	 *            Component within container to apply to
	 */
	public static void setCursorFree(JComponent component) {
		JDialog dialog = findContainingDialog(component);

		if (dialog != null) {
			setCursorFree(dialog);
		} else {
			JFrame frame = findContainingFrame(component);

			if (frame != null) {
				setCursorFree(frame);
			}
		}
	}

	private static JDialog findContainingDialog(JComponent component) {
		Container container = component.getParent();

		while (container != null) {
			if (container instanceof JDialog) {
				return (JDialog) container;
			}

			container = container.getParent();
		}

		return null;
	}

	private static JFrame findContainingFrame(JComponent component) {
		Container container = component.getParent();

		while (container != null) {
			if (container instanceof JFrame) {
				return (JFrame) container;
			}

			container = container.getParent();
		}

		return null;
	}

	/**
	 * Set cursor to busy and disable application input. This can be reversed by
	 * a subsequent call to setCursorFree.
	 *
	 * @param dialog
	 *            Dialog to apply to
	 */
	public static void setCursorBusy(JDialog dialog) {
		setCursorBusy(dialog.getRootPane().getGlassPane());
	}

	/**
	 * Set cursor to free and enable application input. Called after a call to
	 * setCursorBusy.
	 *
	 * @param dialog
	 *            Dialog to apply to
	 */
	public static void setCursorFree(JDialog dialog) {
		setCursorFree(dialog.getRootPane().getGlassPane());
	}

	private static void setCursorBusy(Component glassPane) {
		glassPane.addMouseListener(new MouseAdapter() {
		});
		glassPane.setVisible(true);

		glassPane.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
	}

	private static void setCursorFree(Component glassPane) {
		glassPane.setVisible(false);

		glassPane.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
	}
}
