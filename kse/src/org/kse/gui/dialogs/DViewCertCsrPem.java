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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.kse.crypto.CryptoException;
import org.kse.crypto.csr.pkcs10.Pkcs10Util;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.io.IOUtils;

/**
 * Displays an X.509 certificate's PEM'd DER encoding and provides the
 * opportunity to export it to file.
 *
 */
public class DViewCertCsrPem extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCopy;
	private JButton jbExport;
	private JPanel jpPem;
	private JScrollPane jspPem;
	private JTextArea jtaPem;

	private X509Certificate cert;
	private PKCS10CertificationRequest pkcs10Csr;

	/**
	 * Creates a new DViewCertCsrPem dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 * @param cert
	 *            Certificate to display encoding for
	 * @throws CryptoException
	 *             A problem was encountered getting the certificate's PEM'd DER
	 *             encoding
	 */
	public DViewCertCsrPem(JFrame parent, String title, X509Certificate cert) throws CryptoException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.cert = cert;
		initComponents();
	}

	/**
	 * Creates new DViewCertCsrPem dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param cert
	 *            Certificate to display encoding for
	 * @throws CryptoException
	 *             A problem was encountered getting the certificate's PEM'd DER
	 *             encoding
	 */
	public DViewCertCsrPem(JDialog parent, String title, X509Certificate cert)
			throws CryptoException {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		this.cert = cert;
		initComponents();
	}

	/**
	 * Creates a new DViewCertCsrPem dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 * @param pkcs10Csr
	 *            PKCS10 CSR to display encoding for
	 * @throws CryptoException
	 *             A problem was encountered getting the certificate's PEM'd DER encoding
	 */
	public DViewCertCsrPem(JFrame parent, String title, PKCS10CertificationRequest pkcs10Csr) throws CryptoException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.pkcs10Csr = pkcs10Csr;
		initComponents();
	}

	/**
	 * Creates new DViewCertCsrPem dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param pkcs10Csr
	 *            PKCS10 CSR to display encoding for
	 * @throws CryptoException
	 *             A problem was encountered getting the certificate's PEM'd DER encoding
	 */
	public DViewCertCsrPem(JDialog parent, String title,
			PKCS10CertificationRequest pkcs10Csr) throws CryptoException {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		this.pkcs10Csr = pkcs10Csr;
		initComponents();
	}

	private void initComponents() throws CryptoException {
		jbOK = new JButton(res.getString("DViewCertCsrPem.jbOK.text"));

		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCopy = new JButton(res.getString("DViewCertCsrPem.jbCopy.text"));
		PlatformUtil.setMnemonic(jbCopy, res.getString("DViewCertCsrPem.jbCopy.mnemonic").charAt(0));
		if (cert != null) {
			jbCopy.setToolTipText(res.getString("DViewCertCsrPem.jbCertCopy.tooltip"));
		} else {
			jbCopy.setToolTipText(res.getString("DViewCertCsrPem.jbCsrCopy.tooltip"));
		}

		jbCopy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCertCsrPem.this);
					copyPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCertCsrPem.this);
				}
			}
		});

		jbExport = new JButton(res.getString("DViewCertCsrPem.jbExport.text"));
		PlatformUtil.setMnemonic(jbExport, res.getString("DViewCertCsrPem.jbExport.mnemonic").charAt(0));
		if (cert != null) {
			jbExport.setToolTipText(res.getString("DViewCertCsrPem.jbCertExport.tooltip"));
		} else {
			jbExport.setToolTipText(res.getString("DViewCertCsrPem.jbCsrExport.tooltip"));
		}
		jbExport.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCertCsrPem.this);
					exportPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCertCsrPem.this);
				}
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, new JButton[] { jbCopy, jbExport }, true);

		jpPem = new JPanel(new BorderLayout());
		jpPem.setBorder(new EmptyBorder(5, 5, 5, 5));

		if (cert != null) {
			jtaPem = new JTextArea(X509CertUtil.getCertEncodedX509Pem(cert));
		} else {
			jtaPem = new JTextArea(Pkcs10Util.getCsrEncodedDerPem(pkcs10Csr));
		}
		jtaPem.setCaretPosition(0);
		jtaPem.setEditable(false);
		jtaPem.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		// JGoodies - keep uneditable color same as editable
		jtaPem.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);

		jspPem = PlatformUtil.createScrollPane(jtaPem, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspPem.setPreferredSize(new Dimension(500, 300));
		jpPem.add(jspPem, BorderLayout.CENTER);

		getContentPane().add(jpPem, BorderLayout.CENTER);
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

	private void okPressed() {
		closeDialog();
	}

	private void copyPressed() {
		String policy = jtaPem.getText();

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(policy);
		clipboard.setContents(copy, copy);
	}

	private void exportPressed() {
		File chosenFile = null;
		FileWriter fw = null;

		String title;
		if (cert != null) {
			title = res.getString("DViewCertCsrPem.ExportPemCertificate.Title");
		} else {
			title = res.getString("DViewCertCsrPem.ExportPemCsr.Title");
		}
		try {
			String certPem = jtaPem.getText();

			JFileChooser chooser = FileChooserFactory.getX509FileChooser();
			chooser.setCurrentDirectory(CurrentDirectory.get());
			chooser.setDialogTitle(title);
			chooser.setMultiSelectionEnabled(false);

			int rtnValue = JavaFXFileChooser.isFxAvailable() ? chooser.showSaveDialog(this)
					: chooser.showDialog(this, res.getString("DViewCertCsrPem.ChooseExportFile.button"));

			if (rtnValue != JFileChooser.APPROVE_OPTION) {
				return;
			}

			chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);

			if (chosenFile.isFile()) {
				String message = MessageFormat.format(res.getString("DViewCertCsrPem.OverWriteFile.message"), chosenFile);

				int selected = JOptionPane.showConfirmDialog(this, message, title, JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}
			}

			fw = new FileWriter(chosenFile);
			fw.write(certPem);
			fw.flush();
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("DViewCertCsrPem.NoWriteFile.message"), chosenFile),
					title, JOptionPane.WARNING_MESSAGE);
			return;
		} catch (Exception ex) {
			DError.displayError(this, ex);
			return;
		} finally {
			IOUtils.closeQuietly(fw);
		}

		JOptionPane.showMessageDialog(this, res.getString("DViewCertCsrPem.ExportPemCertificateSuccessful.message"),
				title, JOptionPane.INFORMATION_MESSAGE);
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
