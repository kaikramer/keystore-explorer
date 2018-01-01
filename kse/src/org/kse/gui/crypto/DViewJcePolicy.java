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
package org.kse.gui.crypto;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import org.kse.crypto.CryptoException;
import org.kse.crypto.jcepolicy.JcePolicy;
import org.kse.crypto.jcepolicy.JcePolicyUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;

/**
 * Displays a JCE Policy.
 *
 */
public class DViewJcePolicy extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

	private JPanel jpButtons;
	private JButton jbCopy;
	private JButton jbOK;
	private JPanel jpPolicy;
	private JScrollPane jspPolicy;
	private JTextArea jtaPolicy;

	private JcePolicy jcePolicy;

	/**
	 * Creates a new DViewJcePolicy dialog where the parent is a frame.
	 *
	 * @param parent
	 *            Parent frame
	 * @param jcePolicy
	 *            JCE Policy
	 * @throws CryptoException
	 *             CryptoException If a crypto problem occurs while viewing the
	 *             JCE Policy
	 */
	public DViewJcePolicy(JFrame parent, JcePolicy jcePolicy) throws CryptoException {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.jcePolicy = jcePolicy;
		initComponents();
	}

	/**
	 * Creates a new DViewJcePolicy dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param jcePolicy
	 *            JCE Policy
	 * @throws CryptoException
	 *             CryptoException If a crypto problem occurs while viewing the
	 *             JCE Policy
	 */
	public DViewJcePolicy(JDialog parent, JcePolicy jcePolicy) throws CryptoException {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.jcePolicy = jcePolicy;
		initComponents();
	}

	private void initComponents() throws CryptoException {
		jbCopy = new JButton(res.getString("DViewJcePolicy.jbCopy.text"));
		PlatformUtil.setMnemonic(jbCopy, res.getString("DViewJcePolicy.jbCopy.mnemonic").charAt(0));
		jbCopy.setToolTipText(res.getString("DViewJcePolicy.jbCopy.tooltip"));
		jbCopy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewJcePolicy.this);
					copyPressed();
				} finally {
					CursorUtil.setCursorFree(DViewJcePolicy.this);
				}
			}
		});

		jbOK = new JButton(res.getString("DViewJcePolicy.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, jbCopy, true);

		jpPolicy = new JPanel(new BorderLayout());
		jpPolicy.setBorder(new EmptyBorder(5, 5, 5, 5));

		jtaPolicy = new JTextArea();
		jtaPolicy.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		jtaPolicy.setEditable(false);
		jtaPolicy.setTabSize(4);
		// JGoodies - keep uneditable color same as editable
		jtaPolicy.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);
		jtaPolicy.setToolTipText(res.getString("DViewJcePolicy.jtaPolicy.tooltip"));

		jtaPolicy.setText(JcePolicyUtil.getPolicyDetails(jcePolicy));
		jtaPolicy.setCaretPosition(0);

		jspPolicy = PlatformUtil.createScrollPane(jtaPolicy, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspPolicy.setPreferredSize(new Dimension(500, 200));
		jpPolicy.add(jspPolicy, BorderLayout.CENTER);

		getContentPane().add(jpPolicy, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setTitle(jcePolicy.friendly());
		setResizable(true);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				jbOK.requestFocus();
			}
		});
	}

	private void copyPressed() {
		String policy = jtaPolicy.getText();

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(policy);
		clipboard.setContents(copy, copy);
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
