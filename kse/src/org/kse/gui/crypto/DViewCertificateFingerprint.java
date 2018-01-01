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
import java.awt.Container;
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
import java.text.MessageFormat;
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
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Dialog to view a certificate fingerprint.
 *
 */
public class DViewCertificateFingerprint extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

	private JPanel jpButtons;
	private JButton jbCopy;
	private JButton jbOK;
	private JPanel jpFingerprint;
	private JScrollPane jspPolicy;
	private JTextArea jtaFingerprint;

	private byte[] encodedCertificate;
	private DigestType fingerprintAlg;

	/**
	 * Creates a new DViewCertificateFingerprint dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param encodedCertificate
	 *            Encoded certificate to fingerprint
	 * @param fingerprintAlg
	 *            Fingerprint algorithm
	 */
	public DViewCertificateFingerprint(JFrame parent, byte[] encodedCertificate, DigestType fingerprintAlg) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.encodedCertificate = encodedCertificate;
		this.fingerprintAlg = fingerprintAlg;
		initComponents();
	}

	/**
	 * Creates a new DViewCertificateFingerprint dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param encodedCertificate
	 *            Encoded certificate to fingerprint
	 * @param fingerprintAlg
	 *            Fingerprint algorithm
	 */
	public DViewCertificateFingerprint(JDialog parent, byte[] encodedCertificate, DigestType fingerprintAlg) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.encodedCertificate = encodedCertificate;
		this.fingerprintAlg = fingerprintAlg;
		initComponents();
	}

	private void initComponents() {
		jbCopy = new JButton(res.getString("DViewCertificateFingerprint.jbCopy.text"));
		PlatformUtil.setMnemonic(jbCopy, res.getString("DViewCertificateFingerprint.jbCopy.mnemonic").charAt(0));
		jbCopy.setToolTipText(res.getString("DViewCertificateFingerprint.jbCopy.tooltip"));
		jbCopy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCertificateFingerprint.this);
					copyPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCertificateFingerprint.this);
				}
			}
		});

		jbOK = new JButton(res.getString("DViewCertificateFingerprint.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, jbCopy, true);

		jpFingerprint = new JPanel(new BorderLayout());
		jpFingerprint.setBorder(new EmptyBorder(5, 5, 5, 5));

		jtaFingerprint = new JTextArea();
		jtaFingerprint.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		jtaFingerprint.setEditable(false);
		jtaFingerprint.setTabSize(4);
		jtaFingerprint.setLineWrap(true);
		// JGoodies - keep uneditable color same as editable
		jtaFingerprint.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);
		jtaFingerprint.setToolTipText(MessageFormat.format(
				res.getString("DViewCertificateFingerprint.jtaFingerprint.tooltip"), fingerprintAlg.friendly()));

		jspPolicy = PlatformUtil.createScrollPane(jtaFingerprint, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspPolicy.setPreferredSize(new Dimension(280, 125));
		jpFingerprint.add(jspPolicy, BorderLayout.CENTER);

		getContentPane().add(jpFingerprint, BorderLayout.CENTER);

		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setTitle(MessageFormat.format(res.getString("DViewCertificateFingerprint.Title"), fingerprintAlg.friendly()));
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

		populateFingerprint();
	}

	private void populateFingerprint() {
		if (encodedCertificate != null) {
			try {
				jtaFingerprint.setText(DigestUtil.getFriendlyMessageDigest(encodedCertificate, fingerprintAlg));
			} catch (CryptoException ex) {
				Container container = this.getParent();

				DError dError = null;

				if (container instanceof JDialog) {
					dError = new DError((JDialog) container, ex);
				} else if (container instanceof JFrame) {
					dError = new DError((JFrame) container, ex);
				}

				dError.setLocationRelativeTo(container);
				dError.setVisible(true);
				return;
			}
		} else {
			jtaFingerprint.setText("");
		}

		jtaFingerprint.setCaretPosition(0);
	}

	private void copyPressed() {
		String fingerprint = jtaFingerprint.getText();

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(fingerprint);
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
