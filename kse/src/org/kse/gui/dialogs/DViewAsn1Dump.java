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
package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.kse.crypto.csr.spkac.Spkac;
import org.kse.crypto.x509.X509Ext;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscFrame;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.asn1.Asn1Dump;
import org.kse.utilities.asn1.Asn1Exception;

/**
 * Displays an ASN.1 dump of the supplied object: an X.509 certificate, private
 * key, public key, CRL or Extension.
 *
 */
public class DViewAsn1Dump extends JEscFrame {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JPanel jpButtons;
	private JButton jbCopy;
	private JButton jbOK;
	private JPanel jpAsn1Dump;
	private JScrollPane jspAsn1Dump;
	private JTextArea jtaAsn1Dump;

	private X509Certificate certificate;
	private X509CRL crl;
	private X509Ext extension;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private PKCS10CertificationRequest pkcs10Csr;
	private Spkac spkac;

	/**
	 * Creates a new DViewAsn1Dump dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param cert
	 *            Certificate to display dump for
	 * @throws Asn1Exception
	 *             A problem was encountered getting the extension's ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public DViewAsn1Dump(JDialog parent, X509Certificate cert) throws Asn1Exception, IOException {
		super(res.getString("DViewAsn1Dump.Certificate.Title"));
		this.certificate = cert;
		initComponents();
	}

	/**
	 * Creates new DViewAsn1Dump dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param crl
	 *            CRL to display dump for
	 * @throws Asn1Exception
	 *             A problem was encountered getting the extension's ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public DViewAsn1Dump(JDialog parent, X509CRL crl) throws Asn1Exception, IOException {
		super(res.getString("DViewAsn1Dump.Crl.Title"));
		this.crl = crl;
		initComponents();
	}

	/**
	 * Creates new DViewAsn1Dump dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param extension
	 *            Extension to display dump for
	 * @throws Asn1Exception
	 *             A problem was encountered getting the extension's ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public DViewAsn1Dump(JDialog parent, X509Ext extension) throws Asn1Exception,
	IOException {
		super(res.getString("DViewAsn1Dump.Extension.Title"));
		this.extension = extension;
		initComponents();
	}

	/**
	 * Creates new DViewAsn1Dump dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param privateKey
	 *            Private key to display dump for
	 * @throws Asn1Exception
	 *             A problem was encountered getting the private key's ASN.1
	 *             dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public DViewAsn1Dump(JDialog parent, PrivateKey privateKey) throws Asn1Exception,
	IOException {
		super(res.getString("DViewAsn1Dump.PrivateKey.Title"));
		this.privateKey = privateKey;
		initComponents();
	}

	/**
	 * Creates new DViewAsn1Dump dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param publicKey
	 *            Public key to display dump for
	 * @throws Asn1Exception
	 *             A problem was encountered getting the public key's ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public DViewAsn1Dump(JDialog parent, PublicKey publicKey) throws Asn1Exception,
	IOException {
		super(res.getString("DViewAsn1Dump.PublicKey.Title"));
		this.publicKey = publicKey;
		initComponents();
	}

	/**
	 * Creates a new DViewAsn1Dump dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param pkcs10Csr
	 *            PKCS#10 request to display dump for
	 * @throws Asn1Exception
	 *             A problem was encountered getting the public key's ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public DViewAsn1Dump(JDialog parent, PKCS10CertificationRequest pkcs10Csr)
			throws Asn1Exception, IOException {
		super(res.getString("DViewAsn1Dump.Csr.Title"));
		this.pkcs10Csr = pkcs10Csr;
		initComponents();
	}

	/**
	 * Creates a new DViewAsn1Dump dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param pkcs10Csr
	 *            PKCS#10 request to display dump for
	 * @throws Asn1Exception
	 *             A problem was encountered getting the public key's ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public DViewAsn1Dump(JDialog parent, Spkac spkac) throws Asn1Exception, IOException {
		super(res.getString("DViewAsn1Dump.Csr.Title"));
		this.spkac = spkac;
		initComponents();
	}

	private void initComponents() throws Asn1Exception, IOException {
		jbCopy = new JButton(res.getString("DViewAsn1Dump.jbCopy.text"));

		PlatformUtil.setMnemonic(jbCopy, res.getString("DViewAsn1Dump.jbCopy.mnemonic").charAt(0));
		jbCopy.setToolTipText(res.getString("DViewAsn1Dump.jbCopy.tooltip"));
		jbCopy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewAsn1Dump.this);
					copyPressed();
				} finally {
					CursorUtil.setCursorFree(DViewAsn1Dump.this);
				}
			}
		});

		jbOK = new JButton(res.getString("DViewAsn1Dump.jbOK.text"));

		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, jbCopy, true);

		jpAsn1Dump = new JPanel(new BorderLayout());
		jpAsn1Dump.setBorder(new EmptyBorder(5, 5, 5, 5));

		Asn1Dump asn1Dump = new Asn1Dump();

		if (certificate != null) {
			jtaAsn1Dump = new JTextArea(asn1Dump.dump(certificate));
		} else if (crl != null) {
			jtaAsn1Dump = new JTextArea(asn1Dump.dump(crl));
		} else if (extension != null) {
			jtaAsn1Dump = new JTextArea(asn1Dump.dump(extension));
		} else if (privateKey != null) {
			jtaAsn1Dump = new JTextArea(asn1Dump.dump(privateKey));
		} else if (publicKey != null) {
			jtaAsn1Dump = new JTextArea(asn1Dump.dump(publicKey));
		} else if (pkcs10Csr != null) {
			jtaAsn1Dump = new JTextArea(asn1Dump.dump(pkcs10Csr.getEncoded()));
		} else {
			jtaAsn1Dump = new JTextArea(asn1Dump.dump(spkac.getEncoded()));
		}

		jtaAsn1Dump.setCaretPosition(0);
		jtaAsn1Dump.setEditable(false);
		jtaAsn1Dump.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		// JGoodies - keep uneditable color same as editable
		jtaAsn1Dump.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);

		jspAsn1Dump = PlatformUtil.createScrollPane(jtaAsn1Dump, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspAsn1Dump.setPreferredSize(new Dimension(500, 300));
		jpAsn1Dump.add(jspAsn1Dump, BorderLayout.CENTER);

		getContentPane().add(jpAsn1Dump, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

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
		String policy = jtaAsn1Dump.getText();

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
