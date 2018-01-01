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

import java.awt.Dialog;
import java.awt.Frame;
import java.awt.GraphicsConfiguration;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JRootPane;
import javax.swing.KeyStroke;

/**
 * Extended dialog class that closes itself when escape key was pressed.
 *
 * This is the usual behavior under Windows and Mac OS.
 *
 */
public class JEscDialog extends JDialog {
	private static final long serialVersionUID = -3773740513817678414L;

	public JEscDialog() {
		this((Frame) null, false);
	}

	public JEscDialog(Frame owner) {
		this(owner, false);
	}

	public JEscDialog(Frame owner, boolean modal) {
		this(owner, null, modal);
	}

	public JEscDialog(Frame owner, String title) {
		this(owner, title, false);
	}

	public JEscDialog(Frame owner, String title, boolean modal) {
		super(owner, title, modal);
	}

	public JEscDialog(Frame owner, String title, boolean modal, GraphicsConfiguration gc) {
		super(owner, title, modal, gc);
	}

	public JEscDialog(Dialog owner) {
		this(owner, false);
	}

	public JEscDialog(Dialog owner, boolean modal) {
		this(owner, null, modal);
	}

	public JEscDialog(Dialog owner, String title) {
		this(owner, title, false);
	}

	public JEscDialog(Dialog owner, String title, boolean modal) {
		super(owner, title, modal);
	}

	public JEscDialog(Dialog owner, String title, boolean modal, GraphicsConfiguration gc) {
		super(owner, title, modal, gc);
	}

	public JEscDialog(Window owner, ModalityType modalityType) {
		this(owner, "", modalityType);
	}

	public JEscDialog(Window owner, String title, Dialog.ModalityType modalityType) {
		super(owner, title, modalityType);
	}

	public JEscDialog(Window owner, String title, Dialog.ModalityType modalityType, GraphicsConfiguration gc) {
		super(owner, title, modalityType, gc);
	}

	@Override
	protected JRootPane createRootPane() {
		JRootPane rootPane = new JRootPane();

		// Escape key closes dialogs
		KeyStroke stroke = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
		rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(stroke, "escapeKey");
		rootPane.getActionMap().put("escapeKey", new AbstractAction() {
			private static final long serialVersionUID = 1L;
			@Override
			public void actionPerformed(ActionEvent e) {
				setVisible(false);
				dispose();
			}
		});
		return rootPane;
	}
}
