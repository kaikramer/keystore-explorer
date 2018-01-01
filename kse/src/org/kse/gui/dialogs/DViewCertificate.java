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
import java.awt.Color;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeSet;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.kse.ApplicationSettings;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.KseFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.actions.ExportTrustedCertificateAction;
import org.kse.gui.actions.ImportTrustedCertificateAction;
import org.kse.gui.crypto.JCertificateFingerprint;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.dialogs.extensions.DViewExtensions;
import org.kse.gui.error.DError;
import org.kse.utilities.StringUtils;
import org.kse.utilities.asn1.Asn1Exception;

/**
 * Displays the details of one or more X.509 certificates. The details of one
 * certificate are displayed at a time with selector buttons allowing the
 * movement to another of the certificates.
 *
 */
public class DViewCertificate extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	public static int NONE = 0;
	public static int IMPORT = 1;
	public static int EXPORT = 2;
	private int importExport = 0;

	private KseFrame kseFrame;

	private JPanel jpCertificates;
	private JPanel jpHierarchy;
	private JLabel jlHierarchy;
	private JTree jtrHierarchy;
	private JScrollPane jspHierarchy;
	private JPanel jpDetail;
	private JLabel jlVersion;
	private JTextField jtfVersion;
	private JLabel jlSubject;
	private JDistinguishedName jdnSubject;
	private JLabel jlIssuer;
	private JDistinguishedName jdnIssuer;
	private JLabel jlSerialNumber;
	private JTextField jtfSerialNumber;
	private JLabel jlValidFrom;
	private JTextField jtfValidFrom;
	private JLabel jlValidUntil;
	private JTextField jtfValidUntil;
	private JLabel jlPublicKey;
	private JPanel jpPublicKey;
	private JTextField jtfPublicKey;
	private JButton jbViewPublicKeyDetails;
	private JLabel jlSignatureAlgorithm;
	private JTextField jtfSignatureAlgorithm;
	private JLabel jlFingerprint;
	private JCertificateFingerprint jcfFingerprint;
	private JPanel jpButtons;
	private JButton jbExtensions;
	private JButton jbPem;
	private JButton jbAsn1;
	private JButton jbImportExport;
	private JPanel jpOK;
	private JButton jbOK;

	/**
	 * Creates a new DViewCertificate dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 * @param certs
	 *            Certificate(s) to display
	 * @param kseFrame
	 *            Reference to main class with currently opened keystores and their contents
	 * @param importExport
	 *            Show import button/export button/no extra button?
	 * @throws CryptoException
	 *             A problem was encountered getting the certificates' details
	 */
	public DViewCertificate(Window parent, String title, X509Certificate[] certs, KseFrame kseFrame, int importExport)
			throws CryptoException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.kseFrame = kseFrame;
		this.importExport = importExport;
		initComponents(certs);
	}

	private void initComponents(X509Certificate[] certs) throws CryptoException {
		jlHierarchy = new JLabel(res.getString("DViewCertificate.jlHierarchy.text"));

		jtrHierarchy = new JTree(createCertificateNodes(certs));
		jtrHierarchy.setRowHeight(Math.max(18, jtrHierarchy.getRowHeight()));
		jtrHierarchy.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		ToolTipManager.sharedInstance().registerComponent(jtrHierarchy);
		jtrHierarchy.setCellRenderer(new CertificateTreeCellRend());
		jtrHierarchy.setRootVisible(false);

		TreeNode topNode = (TreeNode) jtrHierarchy.getModel().getRoot();
		expandTree(jtrHierarchy, new TreePath(topNode));

		jtrHierarchy.addTreeSelectionListener(new TreeSelectionListener() {
			@Override
			public void valueChanged(TreeSelectionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCertificate.this);
					populateDetails();
				} finally {
					CursorUtil.setCursorFree(DViewCertificate.this);
				}
			}
		});

		jspHierarchy = PlatformUtil.createScrollPane(jtrHierarchy, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspHierarchy.setPreferredSize(new Dimension(100, 75));

		jpHierarchy = new JPanel(new BorderLayout(5, 5));
		jpHierarchy.add(jlHierarchy, BorderLayout.NORTH);
		jpHierarchy.add(jspHierarchy, BorderLayout.CENTER);

		jpHierarchy.setBorder(new EmptyBorder(5, 5, 5, 5));

		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 1;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcCtrl = new GridBagConstraints();
		gbcCtrl.gridx = 1;
		gbcCtrl.gridwidth = 1;
		gbcCtrl.gridheight = 1;
		gbcCtrl.insets = new Insets(5, 5, 5, 5);
		gbcCtrl.anchor = GridBagConstraints.WEST;

		jlVersion = new JLabel(res.getString("DViewCertificate.jlVersion.text"));
		GridBagConstraints gbc_jlVersion = (GridBagConstraints) gbcLbl.clone();
		gbc_jlVersion.gridy = 0;

		jtfVersion = new JTextField(3);
		jtfVersion.setEditable(false);
		jtfVersion.setToolTipText(res.getString("DViewCertificate.jtfVersion.tooltip"));
		GridBagConstraints gbc_jtfVersion = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfVersion.gridy = 0;

		jlSubject = new JLabel(res.getString("DViewCertificate.jlSubject.text"));
		GridBagConstraints gbc_jlSubject = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSubject.gridy = 1;

		jdnSubject = new JDistinguishedName(res.getString("DViewCertificate.Subject.Title"), 40, false);
		jdnSubject.setToolTipText(res.getString("DViewCertificate.jdnSubject.tooltip"));
		GridBagConstraints gbc_jdnSubject = (GridBagConstraints) gbcCtrl.clone();
		gbc_jdnSubject.gridy = 1;

		jlIssuer = new JLabel(res.getString("DViewCertificate.jlIssuer.text"));
		GridBagConstraints gbc_jlIssuer = (GridBagConstraints) gbcLbl.clone();
		gbc_jlIssuer.gridy = 2;

		jdnIssuer = new JDistinguishedName(res.getString("DViewCertificate.Issuer.Title"), 40, false);
		jdnIssuer.setToolTipText(res.getString("DViewCertificate.jdnIssuer.tooltip"));
		GridBagConstraints gbc_jdnIssuer = (GridBagConstraints) gbcCtrl.clone();
		gbc_jdnIssuer.gridy = 2;

		jlSerialNumber = new JLabel(res.getString("DViewCertificate.jlSerialNumber.text"));
		GridBagConstraints gbc_jlSerialNumber = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSerialNumber.gridy = 3;

		jtfSerialNumber = new JTextField(30);
		jtfSerialNumber.setEditable(false);
		jtfSerialNumber.setToolTipText(res.getString("DViewCertificate.jtfSerialNumber.tooltip"));
		GridBagConstraints gbc_jtfSerialNumber = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfSerialNumber.gridy = 3;

		jlValidFrom = new JLabel(res.getString("DViewCertificate.jlValidFrom.text"));
		GridBagConstraints gbc_jlValidFrom = (GridBagConstraints) gbcLbl.clone();
		gbc_jlValidFrom.gridy = 4;

		jtfValidFrom = new JTextField(30);
		jtfValidFrom.setEditable(false);
		jtfValidFrom.setToolTipText(res.getString("DViewCertificate.jtfValidFrom.tooltip"));
		GridBagConstraints gbc_jtfValidFrom = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfValidFrom.gridy = 4;

		jlValidUntil = new JLabel(res.getString("DViewCertificate.jlValidUntil.text"));
		GridBagConstraints gbc_jlValidUntil = (GridBagConstraints) gbcLbl.clone();
		gbc_jlValidUntil.gridy = 5;

		jtfValidUntil = new JTextField(30);
		jtfValidUntil.setEditable(false);
		jtfValidUntil.setToolTipText(res.getString("DViewCertificate.jtfValidUntil.tooltip"));
		GridBagConstraints gbc_jtfValidUntil = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfValidUntil.gridy = 5;

		jlPublicKey = new JLabel(res.getString("DViewCertificate.jlPublicKey.text"));
		GridBagConstraints gbc_jlPublicKey = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPublicKey.gridy = 6;

		jtfPublicKey = new JTextField(15);
		jtfPublicKey.setEditable(false);
		jtfPublicKey.setToolTipText(res.getString("DViewCertificate.jtfPublicKey.tooltip"));

		jbViewPublicKeyDetails = new JButton();
		jbViewPublicKeyDetails.setToolTipText(res.getString("DViewCertificate.jbViewPublicKeyDetails.tooltip"));
		jbViewPublicKeyDetails.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("DViewCertificate.jbViewPublicKeyDetails.image")))));
		jbViewPublicKeyDetails.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCertificate.this);
					pubKeyDetailsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCertificate.this);
				}
			}
		});

		jpPublicKey = new JPanel(new GridBagLayout());
		GridBagConstraints gbc_jpPublicKey = (GridBagConstraints) gbcCtrl.clone();
		gbc_jpPublicKey.gridy = 6;

		GridBagConstraints gbc_jtfPublicKey = new GridBagConstraints();
		gbc_jtfPublicKey.gridwidth = 1;
		gbc_jtfPublicKey.gridheight = 1;
		gbc_jtfPublicKey.gridx = 0;
		gbc_jtfPublicKey.gridy = 0;
		gbc_jtfPublicKey.insets = new Insets(0, 0, 0, 5);

		GridBagConstraints gbc_jbViewPublicKeyDetails = new GridBagConstraints();
		gbc_jbViewPublicKeyDetails.gridwidth = 1;
		gbc_jbViewPublicKeyDetails.gridheight = 1;
		gbc_jbViewPublicKeyDetails.gridx = 1;
		gbc_jbViewPublicKeyDetails.gridy = 0;
		gbc_jbViewPublicKeyDetails.insets = new Insets(0, 5, 0, 0);

		jpPublicKey.add(jtfPublicKey, gbc_jtfPublicKey);
		jpPublicKey.add(jbViewPublicKeyDetails, gbc_jbViewPublicKeyDetails);

		jlSignatureAlgorithm = new JLabel(res.getString("DViewCertificate.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = 7;

		jtfSignatureAlgorithm = new JTextField(15);
		jtfSignatureAlgorithm.setEditable(false);
		jtfSignatureAlgorithm.setToolTipText(res.getString("DViewCertificate.jtfSignatureAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfSignatureAlgorithm = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfSignatureAlgorithm.gridy = 7;

		jlFingerprint = new JLabel(res.getString("DViewCertificate.jlFingerprint.text"));
		GridBagConstraints gbc_jlFingerprint = (GridBagConstraints) gbcLbl.clone();
		gbc_jlFingerprint.gridy = 8;

		jcfFingerprint = new JCertificateFingerprint(30);
		GridBagConstraints gbc_jcfFingerprint = (GridBagConstraints) gbcCtrl.clone();
		gbc_jcfFingerprint.gridy = 8;

		jbExtensions = new JButton(res.getString("DViewCertificate.jbExtensions.text"));

		PlatformUtil.setMnemonic(jbExtensions, res.getString("DViewCertificate.jbExtensions.mnemonic").charAt(0));
		jbExtensions.setToolTipText(res.getString("DViewCertificate.jbExtensions.tooltip"));
		jbExtensions.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCertificate.this);
					extensionsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCertificate.this);
				}
			}
		});

		jbPem = new JButton(res.getString("DViewCertificate.jbPem.text"));

		PlatformUtil.setMnemonic(jbPem, res.getString("DViewCertificate.jbPem.mnemonic").charAt(0));
		jbPem.setToolTipText(res.getString("DViewCertificate.jbPem.tooltip"));
		jbPem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCertificate.this);
					pemEncodingPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCertificate.this);
				}
			}
		});

		jbAsn1 = new JButton(res.getString("DViewCertificate.jbAsn1.text"));

		PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewCertificate.jbAsn1.mnemonic").charAt(0));
		jbAsn1.setToolTipText(res.getString("DViewCertificate.jbAsn1.tooltip"));
		jbAsn1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCertificate.this);
					asn1DumpPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCertificate.this);
				}
			}
		});

		if (importExport == IMPORT) {
			jbImportExport = new JButton(res.getString("DViewCertificate.jbImportExport.import.text"));
			jbImportExport.setToolTipText(res.getString("DViewCertificate.jbImportExport.import.tooltip"));
		} else {
			jbImportExport = new JButton(res.getString("DViewCertificate.jbImportExport.export.text"));
			jbImportExport.setToolTipText(res.getString("DViewCertificate.jbImportExport.export.tooltip"));
		}

		PlatformUtil.setMnemonic(jbImportExport, res.getString("DViewCertificate.jbImportExport.mnemonic").charAt(0));
		jbImportExport.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCertificate.this);
					importExportPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCertificate.this);
				}
			}
		});

		jpButtons = new JPanel();
		if (importExport != NONE) {
			jpButtons.add(jbImportExport);
		}
		jpButtons.add(jbExtensions);
		jpButtons.add(jbPem);
		jpButtons.add(jbAsn1);

		GridBagConstraints gbc_jpButtons = new GridBagConstraints();
		gbc_jpButtons.gridx = 0;
		gbc_jpButtons.gridy = 9;
		gbc_jpButtons.gridwidth = 2;
		gbc_jpButtons.gridheight = 1;
		gbc_jpButtons.anchor = GridBagConstraints.EAST;

		jpDetail = new JPanel(new GridBagLayout());
		jpDetail.setBorder(new EmptyBorder(5, 5, 5, 5));

		jpDetail.add(jlVersion, gbc_jlVersion);
		jpDetail.add(jtfVersion, gbc_jtfVersion);
		jpDetail.add(jlSubject, gbc_jlSubject);
		jpDetail.add(jdnSubject, gbc_jdnSubject);
		jpDetail.add(jlIssuer, gbc_jlIssuer);
		jpDetail.add(jdnIssuer, gbc_jdnIssuer);
		jpDetail.add(jlSerialNumber, gbc_jlSerialNumber);
		jpDetail.add(jtfSerialNumber, gbc_jtfSerialNumber);
		jpDetail.add(jlValidFrom, gbc_jlValidFrom);
		jpDetail.add(jtfValidFrom, gbc_jtfValidFrom);
		jpDetail.add(jlValidUntil, gbc_jlValidUntil);
		jpDetail.add(jtfValidUntil, gbc_jtfValidUntil);
		jpDetail.add(jlPublicKey, gbc_jlPublicKey);
		jpDetail.add(jpPublicKey, gbc_jpPublicKey);
		jpDetail.add(jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
		jpDetail.add(jtfSignatureAlgorithm, gbc_jtfSignatureAlgorithm);
		jpDetail.add(jlFingerprint, gbc_jlFingerprint);
		jpDetail.add(jcfFingerprint, gbc_jcfFingerprint);
		jpDetail.add(jpButtons, gbc_jpButtons);

		jpCertificates = new JPanel(new BorderLayout(0, 0));
		jpCertificates.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));
		jpCertificates.add(jpHierarchy, BorderLayout.NORTH);
		jpCertificates.add(jpDetail, BorderLayout.CENTER);

		jbOK = new JButton(res.getString("DViewCertificate.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpOK = PlatformUtil.createDialogButtonPanel(jbOK, false);

		getContentPane().add(jpCertificates, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		jtrHierarchy.setSelectionRow(0);

		setResizable(false);

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

	private DefaultMutableTreeNode createCertificateNodes(X509Certificate[] certs) {
		DefaultMutableTreeNode certsNode = new DefaultMutableTreeNode();

		TreeSet<X509Certificate> certSet = new TreeSet<X509Certificate>(new X509CertificateComparator());
		Collections.addAll(certSet, certs);

		// TODO rewrite
		setcheck: while (certSet.size() > 0) {
			certs: for (X509Certificate cert : certSet) {
				if (X509CertUtil.isCertificateSelfSigned(cert)) {
					certsNode.add(new DefaultMutableTreeNode(cert));
					certSet.remove(cert);
					continue setcheck;
				}

				DefaultMutableTreeNode issuerNode = findIssuer(cert, certsNode);

				if (issuerNode != null) {
					issuerNode.add(new DefaultMutableTreeNode(cert));
					certSet.remove(cert);
					continue setcheck;
				}

				if (isIssuerInSet(cert, certSet)) {
					continue certs;
				} else {
					certsNode.add(new DefaultMutableTreeNode(cert));
					certSet.remove(cert);
					continue setcheck;
				}
			}
		}

		return certsNode;
	}

	private DefaultMutableTreeNode findIssuer(X509Certificate cert, DefaultMutableTreeNode node) {
		// Matches on certificate's distinguished name

		// If certificate is self-signed then finding an issuer is irrelevant
		if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
			return null;
		}

		Object nodeObj = node.getUserObject();

		if (nodeObj instanceof X509Certificate) {
			X509Certificate nodeCert = (X509Certificate) nodeObj;

			if (cert.getIssuerX500Principal().equals(nodeCert.getSubjectX500Principal())) {
				return node;
			}
		}

		for (int i = 0; i < node.getChildCount(); i++) {
			DefaultMutableTreeNode issuerNode = findIssuer(cert, (DefaultMutableTreeNode) node.getChildAt(i));

			if (issuerNode != null) {
				return issuerNode;
			}
		}

		return null;
	}

	private boolean isIssuerInSet(X509Certificate cert, TreeSet<X509Certificate> certSet) {
		// Matches on certificate's distinguished name

		// If certificate is self-signed then finding an issuer is irrelevant
		if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
			return false;
		}

		for (X509Certificate certToTest : certSet) {
			if (cert.getIssuerX500Principal().equals(certToTest.getSubjectX500Principal())) {
				return true;
			}
		}

		return false;
	}

	private void expandTree(JTree tree, TreePath parent) {
		TreeNode node = (TreeNode) parent.getLastPathComponent();
		if (node.getChildCount() >= 0) {
			for (Enumeration<?> enumNodes = node.children(); enumNodes.hasMoreElements();) {
				TreeNode subNode = (TreeNode) enumNodes.nextElement();
				TreePath path = parent.pathByAddingChild(subNode);
				expandTree(tree, path);
			}
		}

		tree.expandPath(parent);
	}

	private X509Certificate getSelectedCertificate() {
		TreePath[] selections = jtrHierarchy.getSelectionPaths();

		if (selections == null) {
			return null;
		}

		return (X509Certificate) ((DefaultMutableTreeNode) selections[0].getLastPathComponent()).getUserObject();
	}

	private void populateDetails() {
		X509Certificate cert = getSelectedCertificate();

		if (cert == null) {
			jdnSubject.setEnabled(false);
			jdnIssuer.setEnabled(false);
			jbViewPublicKeyDetails.setEnabled(false);
			jcfFingerprint.setEnabled(false);
			jbExtensions.setEnabled(false);
			jbPem.setEnabled(false);
			jbAsn1.setEnabled(false);

			jtfVersion.setText("");
			jdnSubject.setDistinguishedName(null);
			jdnIssuer.setDistinguishedName(null);
			jtfSerialNumber.setText("");
			jtfValidFrom.setText("");
			jtfValidUntil.setText("");
			jtfPublicKey.setText("");
			jtfSignatureAlgorithm.setText("");
			jcfFingerprint.setEncodedCertificate(null);
		} else {
			jdnSubject.setEnabled(true);
			jdnIssuer.setEnabled(true);
			jbViewPublicKeyDetails.setEnabled(true);
			jbExtensions.setEnabled(true);
			jbPem.setEnabled(true);
			jbAsn1.setEnabled(true);

			try {
				Date currentDate = new Date();

				Date startDate = cert.getNotBefore();
				Date endDate = cert.getNotAfter();

				boolean notYetValid = currentDate.before(startDate);
				boolean noLongerValid = currentDate.after(endDate);

				jtfVersion.setText(Integer.toString(cert.getVersion()));
				jtfVersion.setCaretPosition(0);

				jdnSubject.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert
						.getSubjectX500Principal()));

				jdnIssuer
				.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert.getIssuerX500Principal()));

				jtfSerialNumber.setText("0x"
						+ new BigInteger(1, cert.getSerialNumber().toByteArray()).toString(16).toUpperCase());
				jtfSerialNumber.setCaretPosition(0);

				jtfValidFrom.setText(StringUtils.formatDate(startDate));

				if (notYetValid) {
					jtfValidFrom.setText(MessageFormat.format(
							res.getString("DViewCertificate.jtfValidFrom.notyetvalid.text"), jtfValidFrom.getText()));
					jtfValidFrom.setForeground(Color.red);
				} else {
					jtfValidFrom.setForeground(jtfVersion.getForeground());
				}
				jtfValidFrom.setCaretPosition(0);

				jtfValidUntil.setText(StringUtils.formatDate(endDate));

				if (noLongerValid) {
					jtfValidUntil.setText(MessageFormat.format(
							res.getString("DViewCertificate.jtfValidUntil.expired.text"), jtfValidUntil.getText()));
					jtfValidUntil.setForeground(Color.red);
				} else {
					jtfValidUntil.setForeground(jtfVersion.getForeground());
				}
				jtfValidUntil.setCaretPosition(0);

				KeyInfo keyInfo = KeyPairUtil.getKeyInfo(cert.getPublicKey());
				jtfPublicKey.setText(keyInfo.getAlgorithm());
				Integer keySize = keyInfo.getSize();

				if (keySize != null) {
					jtfPublicKey.setText(MessageFormat.format(res.getString("DViewCertificate.jtfPublicKey.text"),
							jtfPublicKey.getText(), "" + keySize));
				} else {
					jtfPublicKey.setText(MessageFormat.format(res.getString("DViewCertificate.jtfPublicKey.text"),
							jtfPublicKey.getText(), "?"));
				}
				jtfPublicKey.setCaretPosition(0);

				jtfSignatureAlgorithm.setText(X509CertUtil.getCertificateSignatureAlgorithm(cert));
				jtfSignatureAlgorithm.setCaretPosition(0);

				byte[] encodedCertificate;
				try {
					encodedCertificate = cert.getEncoded();
				} catch (CertificateEncodingException ex) {
					throw new CryptoException(res.getString("DViewCertificate.NoGetEncodedCert.exception.message"), ex);
				}

				jcfFingerprint.setEncodedCertificate(encodedCertificate);

				jcfFingerprint.setFingerprintAlg(ApplicationSettings.getInstance().getCertificateFingerprintType());

				Set<?> critExts = cert.getCriticalExtensionOIDs();
				Set<?> nonCritExts = cert.getNonCriticalExtensionOIDs();

				if (critExts != null && critExts.size() != 0
						|| nonCritExts != null && nonCritExts.size() != 0) {
					jbExtensions.setEnabled(true);
				} else {
					jbExtensions.setEnabled(false);
				}
			} catch (CryptoException ex) {
				DError dError = new DError(this, ex);
				dError.setLocationRelativeTo(this);
				dError.setVisible(true);
				dispose();
			}
		}
	}

	private void pubKeyDetailsPressed() {
		try {
			X509Certificate cert = getSelectedCertificate();

			DViewPublicKey dViewPublicKey = new DViewPublicKey(this,
					res.getString("DViewCertificate.PubKeyDetails.Title"),
					cert.getPublicKey());
			dViewPublicKey.setLocationRelativeTo(this);
			dViewPublicKey.setVisible(true);
		} catch (CryptoException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		}
	}

	private void extensionsPressed() {
		X509Certificate cert = getSelectedCertificate();

		DViewExtensions dViewExtensions = new DViewExtensions(this, res.getString("DViewCertificate.Extensions.Title"),
				cert);
		dViewExtensions.setLocationRelativeTo(this);
		dViewExtensions.setVisible(true);
	}

	private void pemEncodingPressed() {
		X509Certificate cert = getSelectedCertificate();

		try {
			DViewPem dViewCertPem = new DViewPem(this, res.getString("DViewCertificate.Pem.Title"),
					cert);
			dViewCertPem.setLocationRelativeTo(this);
			dViewCertPem.setVisible(true);
		} catch (CryptoException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		}
	}

	private void asn1DumpPressed() {
		X509Certificate cert = getSelectedCertificate();

		try {
			DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, cert);
			dViewAsn1Dump.setLocationRelativeTo(this);
			dViewAsn1Dump.setVisible(true);
		} catch (Asn1Exception ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		} catch (IOException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		}
	}

	private void importExportPressed() {
		X509Certificate cert = getSelectedCertificate();

		if (importExport == IMPORT) {
			new ImportTrustedCertificateAction(kseFrame, cert).actionPerformed(null);
		} else {
			new ExportTrustedCertificateAction(kseFrame, cert).actionPerformed(null);
		}
	}

	private void okPressed() {
		ApplicationSettings.getInstance().setCertificateFingerprintType(jcfFingerprint.getSelectedFingerprintAlg());
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private class X509CertificateComparator implements Comparator<X509Certificate> {

		/* (non-Javadoc)
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		@Override
		public int compare(X509Certificate cert1, X509Certificate cert2) {

			// Compare certificates for equality. Where all we care about is if
			// the certificates are equal or not - the order is unimportant
			if (cert1.equals(cert2)) {
				return 0;
			}

			// Compare on subject DN
			int i = cert1.getSubjectX500Principal().toString().compareTo(cert2.getSubjectX500Principal().toString());

			if (i != 0) {
				return i;
			}

			// Compare on issuer DN
			i = cert1.getIssuerX500Principal().toString().compareTo(cert2.getIssuerX500Principal().toString());

			if (i != 0) {
				return i;
			}

			// If all else fails then compare serial numbers - if this is the
			// same and the DNs are the same then it is probably the same
			// certificate anyway
			return cert1.getSerialNumber().subtract(cert2.getSerialNumber()).intValue();
		}
	}
}
