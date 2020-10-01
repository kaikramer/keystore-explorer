/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
package org.kse.gui.dialogs.extensions;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.crypto.CryptoException;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.publickey.KeyIdentifierGenerator;
import org.kse.crypto.x509.ExtendedKeyUsageType;
import org.kse.crypto.x509.X509Ext;
import org.kse.crypto.x509.X509ExtensionSet;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Allows selection of X.509 Extensions to add to a certificate.
 *
 */
public class DSelectStandardExtensionTemplate extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JRadioButton jrbCA;
	private JRadioButton jrbSslServer;
	private JRadioButton jrbSslClient;
	private JRadioButton jrbCodeSigning;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private X509ExtensionSet extensions = new X509ExtensionSet();

	private PublicKey authorityPublicKey;
	private PublicKey subjectPublicKey;

	private boolean cancelled = true;

	/**
	 * Creates a new DSelectStandardExtensionTemplate dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 */
	public DSelectStandardExtensionTemplate(JDialog parent, PublicKey authorityPublicKey, PublicKey subjectPublicKey) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.authorityPublicKey = authorityPublicKey;
		this.subjectPublicKey = subjectPublicKey;
		setTitle(res.getString("DSelectStandardExtensionTemplate.Title"));
		initComponents();
	}

	private void initComponents() {

		jrbCA = new JRadioButton(res.getString("DSelectStandardExtensionTemplate.jrbCA.text"), false);
		PlatformUtil.setMnemonic(jrbCA, res.getString("DSelectStandardExtensionTemplate.jrbCA.mnemonic").charAt(0));
		jrbCA.setToolTipText(res.getString("DSelectStandardExtensionTemplate.jrbCA.tooltip"));
		jrbCA.setSelected(true);

		jrbSslServer = new JRadioButton(res.getString("DSelectStandardExtensionTemplate.jrbSslServer.text"), false);
		PlatformUtil.setMnemonic(jrbSslServer, res.getString("DSelectStandardExtensionTemplate.jrbSslServer.mnemonic").charAt(0));
		jrbSslServer.setToolTipText(res.getString("DSelectStandardExtensionTemplate.jrbSslServer.tooltip"));

		jrbSslClient = new JRadioButton(res.getString("DSelectStandardExtensionTemplate.jrbSslClient.text"), false);
		PlatformUtil.setMnemonic(jrbSslClient, res.getString("DSelectStandardExtensionTemplate.jrbSslClient.mnemonic").charAt(0));
		jrbSslClient.setToolTipText(res.getString("DSelectStandardExtensionTemplate.jrbSslClient.tooltip"));

		jrbCodeSigning = new JRadioButton(res.getString("DSelectStandardExtensionTemplate.jrbCodeSigning.text"), false);
		PlatformUtil.setMnemonic(jrbCodeSigning, res.getString("DSelectStandardExtensionTemplate.jrbCodeSigning.mnemonic").charAt(0));
		jrbCodeSigning.setToolTipText(res.getString("DSelectStandardExtensionTemplate.jrbCodeSigning.tooltip"));

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbCA);
		buttonGroup.add(jrbSslServer);
		buttonGroup.add(jrbSslClient);
		buttonGroup.add(jrbCodeSigning);

		jbOK = new JButton(res.getString("DAddExtensions.jbOK.text"));

		jbCancel = new JButton(res.getString("DAddExtensions.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("fill", "[]", "[]"));
		pane.add(jrbCA, "growx, wrap");
		pane.add(jrbSslServer, "wrap");
		pane.add(jrbSslClient, "wrap");
		pane.add(jrbCodeSigning, "wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap");
		pane.add(jpButtons, "right, spanx");

		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	public X509ExtensionSet getExtensionSet() {
		return extensions;
	}

	public boolean wasCancelled() {
		return cancelled;
	}

	private void okPressed() {
		setExtensionsAsSelected();
		closeDialog();
	}

	private void setExtensionsAsSelected() {

		X509ExtensionSet extensionSet = new X509ExtensionSet();
		try {
			addAuthorityKeyIdentifier(extensionSet);
			addSubjectKeyIdentifier(extensionSet);

			if (jrbCA.isSelected()) {
				addBasicConstraints(extensionSet);
				addKeyUsage(extensionSet, KeyUsage.keyCertSign | KeyUsage.cRLSign);
			}

			if (jrbSslClient.isSelected()) {
				addKeyUsage(extensionSet, KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
				addExtKeyUsage(extensionSet, ExtendedKeyUsageType.CLIENT_AUTH.oid());
			}

			if (jrbSslServer.isSelected()) {
				addKeyUsage(extensionSet, KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
				addExtKeyUsage(extensionSet, ExtendedKeyUsageType.SERVER_AUTH.oid());
			}

			if (jrbCodeSigning.isSelected()) {
				addKeyUsage(extensionSet, KeyUsage.digitalSignature);
				addExtKeyUsage(extensionSet, ExtendedKeyUsageType.CODE_SIGNING.oid());
			}

			this.extensions = extensionSet;

			this.cancelled = false;
		} catch (CryptoException | IOException e) {
			DError.displayError(this, e);
		}
	}

	private void addAuthorityKeyIdentifier(X509ExtensionSet extensionSet) throws CryptoException, IOException {
		KeyIdentifierGenerator akiGenerator = new KeyIdentifierGenerator(authorityPublicKey);
		AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(akiGenerator.generate160BitHashId());
		byte[] akiEncoded = X509Ext.wrapInOctetString(aki.getEncoded());
		extensionSet.addExtension(X509ExtensionType.AUTHORITY_KEY_IDENTIFIER.oid(), false, akiEncoded);
	}

	private void addSubjectKeyIdentifier(X509ExtensionSet extensionSet) throws CryptoException, IOException {
		KeyIdentifierGenerator skiGenerator = new KeyIdentifierGenerator(subjectPublicKey);
		SubjectKeyIdentifier ski = new SubjectKeyIdentifier(skiGenerator.generate160BitHashId());
		byte[] skiEncoded = X509Ext.wrapInOctetString(ski.getEncoded());
		extensionSet.addExtension(X509ExtensionType.SUBJECT_KEY_IDENTIFIER.oid(), false, skiEncoded);
	}

	private void addBasicConstraints(X509ExtensionSet extensionSet) throws IOException {
		BasicConstraints bc = new BasicConstraints(true);
		byte[] bcEncoded = X509Ext.wrapInOctetString(bc.getEncoded());
		extensionSet.addExtension(X509ExtensionType.BASIC_CONSTRAINTS.oid(), true, bcEncoded);
	}

	private void addKeyUsage(X509ExtensionSet extensionSet, int usage) throws IOException {
		KeyUsage ku = new KeyUsage(usage);
		byte[] kuEncoded = X509Ext.wrapInOctetString(ku.getEncoded());
		extensionSet.addExtension(X509ExtensionType.KEY_USAGE.oid(), true, kuEncoded);
	}

	private void addExtKeyUsage(X509ExtensionSet extensionSet, String ekuOid) throws IOException {
		ExtendedKeyUsage eku = new ExtendedKeyUsage(
				new KeyPurposeId[] { KeyPurposeId.getInstance(new ASN1ObjectIdentifier(ekuOid)) });
		byte[] ekuEncoded = X509Ext.wrapInOctetString(eku.getEncoded());
		extensionSet.addExtension(X509ExtensionType.EXTENDED_KEY_USAGE.oid(), false, ekuEncoded);
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	// for quick UI testing
	public static void main(String[] args) throws Exception {
		final KeyPair issuerKP = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 1024, new BouncyCastleProvider());
		final KeyPair subjectKP = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 1024, new BouncyCastleProvider());

		DSelectStandardExtensionTemplate dialog = new DSelectStandardExtensionTemplate(new JDialog(),
				issuerKP.getPublic(), subjectKP.getPublic());
		DialogViewer.run(dialog);
	}
}
