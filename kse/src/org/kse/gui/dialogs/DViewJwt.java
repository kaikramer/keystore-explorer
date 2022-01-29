/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2022 Kai Kramer
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

package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;
import net.miginfocom.swing.MigLayout;

/**
 * Dialog that displays the JSON Web Token (JWT).
 *
 */
public class DViewJwt extends JEscDialog {

	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JPanel jpJwt;
	private JScrollPane jspJwt;
	private JTextArea jtAreaJwt;
	private JButton jbOK;
	private JButton jbCopy;

	/**
	 * Creates a new DViewJwt dialog.
	 *
	 * @param parent The parent frame
	 * @param jwt    The encoded JWT
	 */
	public DViewJwt(JFrame parent, String jwt) {

		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DViewJwt.Title"));
		initComponents(jwt);
	}

	private void initComponents(String jwt) {
		jpJwt = new JPanel(new BorderLayout());
		jpJwt.setBorder(new EmptyBorder(5, 5, 5, 5));

		jtAreaJwt = new JTextArea(jwt);
		jtAreaJwt.setToolTipText(res.getString("DViewJwt.jtAreaJwt.tooltip"));
		jtAreaJwt.setEditable(false);
		jtAreaJwt.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		// keep uneditable color same as editable
		jtAreaJwt.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);
		jtAreaJwt.setLineWrap(true);
		jspJwt = PlatformUtil.createScrollPane(jtAreaJwt, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspJwt.setPreferredSize(new Dimension(400, 200));
		jpJwt.add(jspJwt, BorderLayout.CENTER);

		jbCopy = new JButton(res.getString("DViewJwt.jbCopy.text"));
		jbCopy.setToolTipText(res.getString("DViewJwt.jbCopy.tooltip"));
		PlatformUtil.setMnemonic(jbCopy, res.getString("DViewJwt.jbCopy.mnemonic").charAt(0));

		jbOK = new JButton(res.getString("DViewJwt.jbOK.text"));

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog"));
		pane.add(jpJwt, "span");
		pane.add(jbCopy, "tag Copy");
		pane.add(jbOK, "tag Ok");

		jbOK.addActionListener(evt -> okPressed());

		jbCopy.addActionListener(evt -> {
			try {
				CursorUtil.setCursorBusy(DViewJwt.this);
				copyPressed();
			} finally {
				CursorUtil.setCursorFree(DViewJwt.this);
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbCopy);

		pack();

		SwingUtilities.invokeLater(() -> jbOK.requestFocus());
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private void copyPressed() {
		String policy = jtAreaJwt.getText();

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(policy);
		clipboard.setContents(copy, copy);
	}

	public static void main(String[] args) throws Exception {
		DViewJwt dialog = new DViewJwt(new javax.swing.JFrame(),
				"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9");
		DialogViewer.run(dialog);
	}

}
