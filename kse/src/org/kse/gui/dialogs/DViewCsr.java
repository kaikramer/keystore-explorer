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

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JSeparator;
import javax.swing.JTextField;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.csr.spkac.Spkac;
import org.kse.crypto.csr.spkac.SpkacSubject;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X509ExtensionSet;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.dialogs.extensions.DViewExtensions;
import org.kse.gui.error.DError;
import org.kse.utilities.asn1.Asn1Exception;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a Certificate Signing Request (CSR).
 *
 */
public class DViewCsr extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JLabel jlFormat;
	private JTextField jtfFormat;
	private JLabel jlSubject;
	private JDistinguishedName jdnSubject;
	private JLabel jlPublicKey;
	private JTextField jtfPublicKey;
	private JButton jbViewPublicKeyDetails;
	private JLabel jlSignatureAlgorithm;
	private JTextField jtfSignatureAlgorithm;
	private JLabel jlChallenge;
	private JTextField jtfChallenge;
	private JLabel jlUnstructuredName;
	private JTextField jtfUnstructuredName;
	private JButton jbExtensions;
	private JButton jbPem;
	private JButton jbAsn1;
	private JButton jbOK;

	private PKCS10CertificationRequest pkcs10Csr;
	private Spkac spkacCsr;

	/**
	 * Creates a new DViewCsr dialog for a PKCS #10 formatted CSR.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param pkcs10Csr
	 *            The PKCS #10 formatted CSR
	 * @throws CryptoException
	 *             A crypto problem was encountered constructing the dialog
	 */
	public DViewCsr(JFrame parent, String title, PKCS10CertificationRequest pkcs10Csr) throws CryptoException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.pkcs10Csr = pkcs10Csr;
		initComponents();
	}

	/**
	 * Creates a new DViewCsr dialog for a SPKAC formatted CSR.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param spkacCsr
	 *            The SPKAC formatted CSR
	 * @throws CryptoException
	 *             A crypto problem was encountered constructing the dialog
	 */
	public DViewCsr(JFrame parent, String title, Spkac spkacCsr) throws CryptoException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.spkacCsr = spkacCsr;
		initComponents();
	}

	private void initComponents() throws CryptoException {

		jlFormat = new JLabel(res.getString("DViewCsr.jlFormat.text"));

		jtfFormat = new JTextField(15);
		jtfFormat.setEditable(false);
		jtfFormat.setToolTipText(res.getString("DViewCsr.jtfFormat.tooltip"));

		jlSubject = new JLabel(res.getString("DViewCsr.jlSubject.text"));

		jdnSubject = new JDistinguishedName(res.getString("DViewCsr.Subject.Title"), 30, false);
		jdnSubject.setToolTipText(res.getString("DViewCsr.jdnSubject.tooltip"));

		jlPublicKey = new JLabel(res.getString("DViewCsr.jlPublicKey.text"));

		jtfPublicKey = new JTextField(15);
		jtfPublicKey.setEditable(false);
		jtfPublicKey.setToolTipText(res.getString("DViewCsr.jtfPublicKey.tooltip"));

		jbViewPublicKeyDetails = new JButton();
		jbViewPublicKeyDetails.setToolTipText(res.getString("DViewCsr.jbViewPublicKeyDetails.tooltip"));
		jbViewPublicKeyDetails.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("DViewCsr.jbViewPublicKeyDetails.image")))));

		jlSignatureAlgorithm = new JLabel(res.getString("DViewCsr.jlSignatureAlgorithm.text"));

		jtfSignatureAlgorithm = new JTextField(15);
		jtfSignatureAlgorithm.setEditable(false);
		jtfSignatureAlgorithm.setToolTipText(res.getString("DViewCsr.jtfSignatureAlgorithm.tooltip"));

		jlChallenge = new JLabel(res.getString("DViewCsr.jlChallenge.text"));

		jtfChallenge = new JTextField(15);
		jtfChallenge.setEditable(false);
		jtfChallenge.setToolTipText(res.getString("DViewCsr.jtfChallenge.tooltip"));

		jlUnstructuredName = new JLabel(res.getString("DViewCsr.jlUnstructuredName.text"));

		jtfUnstructuredName = new JTextField(30);
		jtfUnstructuredName.setEditable(false);
		jtfUnstructuredName.setToolTipText(res.getString("DViewCsr.jtfUnstructuredName.tooltip"));

		jbExtensions = new JButton(res.getString("DViewCsr.jbExtensions.text"));

		PlatformUtil.setMnemonic(jbExtensions, res.getString("DViewCsr.jbExtensions.mnemonic").charAt(0));
		jbExtensions.setToolTipText(res.getString("DViewCsr.jbExtensions.tooltip"));

		jbPem = new JButton(res.getString("DViewCsr.jbPem.text"));

		PlatformUtil.setMnemonic(jbPem, res.getString("DViewCsr.jbPem.mnemonic").charAt(0));
		jbPem.setToolTipText(res.getString("DViewCsr.jbPem.tooltip"));

		jbAsn1 = new JButton(res.getString("DViewCsr.jbAsn1.text"));
		PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewCsr.jbAsn1.mnemonic").charAt(0));
		jbAsn1.setToolTipText(res.getString("DViewCsr.jbAsn1.tooltip"));

		jbOK = new JButton(res.getString("DViewCsr.jbOK.text"));

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
		pane.add(jlFormat, "");
		pane.add(jtfFormat, "wrap");
		pane.add(jlSubject, "");
		pane.add(jdnSubject, "wrap");
		pane.add(jlPublicKey, "");
		pane.add(jtfPublicKey, "split 2");
		pane.add(jbViewPublicKeyDetails, "wrap");
		pane.add(jlSignatureAlgorithm, "");
		pane.add(jtfSignatureAlgorithm, "wrap");
		pane.add(jlChallenge, "");
		pane.add(jtfChallenge, "wrap");
		pane.add(jlUnstructuredName, "");
		pane.add(jtfUnstructuredName, "wrap para");
		pane.add(jbExtensions, "spanx, split");
		pane.add(jbPem, "");
		pane.add(jbAsn1, "wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
		pane.add(jbOK, "spanx, tag ok");

		populateCsrDetails();

		jbViewPublicKeyDetails.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCsr.this);
					pubKeyDetailsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCsr.this);
				}
			}
		});

		jbExtensions.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCsr.this);
					extensionsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCsr.this);
				}
			}
		});

		jbPem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCsr.this);
					pemEncodingPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCsr.this);
				}
			}
		});

		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbAsn1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCsr.this);
					asn1DumpPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCsr.this);
				}
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

	private void populateCsrDetails() throws CryptoException {
		if (pkcs10Csr != null) {
			populatePkcs10CsrDetails();
		} else {
			populateSpkacCsrDetails();
		}
	}

	private void populatePkcs10CsrDetails() throws CryptoException {
		jtfFormat.setText(res.getString("DViewCsr.jtfFormat.Pkcs10.text"));
		jtfFormat.setCaretPosition(0);

		jdnSubject.setDistinguishedName(pkcs10Csr.getSubject());

		jbPem.setEnabled(true);
		jbAsn1.setEnabled(true);

		Attribute[] extReqAttr = pkcs10Csr.getAttributes(pkcs_9_at_extensionRequest);
		if (extReqAttr != null && extReqAttr.length > 0) {
			jbExtensions.setEnabled(true);
		} else {
			jbExtensions.setEnabled(false);
		}

		DialogHelper.populatePkcs10Challenge(pkcs10Csr.getAttributes(), jtfChallenge);
		DialogHelper.populatePkcs10UnstructuredName(pkcs10Csr.getAttributes(), jtfUnstructuredName);

		populatePublicKey(getPkcs10PublicKey());

		String sigAlgId = pkcs10Csr.getSignatureAlgorithm().getAlgorithm().getId();
		SignatureType sigAlg = SignatureType.resolveOid(sigAlgId);

		if (sigAlg != null) {
			jtfSignatureAlgorithm.setText(sigAlg.friendly());
		} else {
			jtfSignatureAlgorithm.setText(sigAlgId);
		}

		jtfSignatureAlgorithm.setCaretPosition(0);
	}

	private void populateSpkacCsrDetails() throws CryptoException {
		jtfFormat.setText(res.getString("DViewCsr.jtfFormat.Spkac.text"));
		jtfFormat.setCaretPosition(0);

		jbExtensions.setEnabled(false);
		jbPem.setEnabled(false);
		jbAsn1.setEnabled(true);

		SpkacSubject subject = spkacCsr.getSubject();
		jdnSubject.setDistinguishedName(subject.getName());

		populatePublicKey(spkacCsr.getPublicKey());

		jtfSignatureAlgorithm.setText(spkacCsr.getSignatureAlgorithm().friendly());
		jtfSignatureAlgorithm.setCaretPosition(0);

		jtfChallenge.setText(spkacCsr.getChallenge());
		jtfChallenge.setCaretPosition(0);
	}

	private void populatePublicKey(PublicKey csrPublicKey) throws CryptoException {
		KeyInfo keyInfo = KeyPairUtil.getKeyInfo(csrPublicKey);

		jtfPublicKey.setText(keyInfo.getAlgorithm());
		Integer keySize = keyInfo.getSize();

		if (keySize != null) {
			jtfPublicKey.setText(MessageFormat.format(res.getString("DViewCsr.jtfPublicKey.text"),
					jtfPublicKey.getText(), "" + keySize));
		} else {
			jtfPublicKey.setText(MessageFormat.format(res.getString("DViewCsr.jtfPublicKey.text"),
					jtfPublicKey.getText(), "?"));
		}

		jtfPublicKey.setCaretPosition(0);
	}

	private PublicKey getPkcs10PublicKey() throws CryptoException {
		try {
			return new JcaPKCS10CertificationRequest(pkcs10Csr).getPublicKey();
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("DViewCsr.NoGetPublicKey.message"), ex);
		}
	}

	private void extensionsPressed() {

		// extract sequence with extensions from csr
		Attribute[] attributes = pkcs10Csr.getAttributes(pkcs_9_at_extensionRequest);
		X509ExtensionSet x509ExtensionSet = new X509ExtensionSet();
		if ((attributes != null) && (attributes.length > 0)) {
			ASN1Encodable[] attributeValues = attributes[0].getAttributeValues();
			if (attributeValues.length > 0) {
				ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(attributeValues[0]);
				x509ExtensionSet = new X509ExtensionSet(asn1Sequence);
			}
		}

		DViewExtensions dViewExtensions = new DViewExtensions(this, res.getString("DViewCertificate.Extensions.Title"),
				x509ExtensionSet);
		dViewExtensions.setLocationRelativeTo(this);
		dViewExtensions.setVisible(true);
	}

	private void pubKeyDetailsPressed() {
		try {
			PublicKey publicKey = null;

			if (pkcs10Csr != null) {
				publicKey = getPkcs10PublicKey();
			} else {
				publicKey = spkacCsr.getPublicKey();
			}

			DViewPublicKey dViewPublicKey = new DViewPublicKey(this, res.getString("DViewCsr.PubKeyDetails.Title"),
					publicKey);
			dViewPublicKey.setLocationRelativeTo(this);
			dViewPublicKey.setVisible(true);
		} catch (CryptoException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		}
	}

	private void pemEncodingPressed() {
		try {
			DViewPem dViewCsrPem = new DViewPem(this, res.getString("DViewCsr.Pem.Title"),
					pkcs10Csr);
			dViewCsrPem.setLocationRelativeTo(this);
			dViewCsrPem.setVisible(true);
		} catch (CryptoException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		}
	}

	private void asn1DumpPressed() {

		try {
			DViewAsn1Dump dViewAsn1Dump;
			if (pkcs10Csr != null) {
				dViewAsn1Dump = new DViewAsn1Dump(this, pkcs10Csr);
			} else {
				dViewAsn1Dump = new DViewAsn1Dump(this, spkacCsr);
			}
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

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	// for quick testing
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		javax.swing.UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
		java.awt.EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
					KeyPair keyPair = keyGen.genKeyPair();
					JcaPKCS10CertificationRequestBuilder csrBuilder =
							new JcaPKCS10CertificationRequestBuilder(new X500Name("cn=test"), keyPair.getPublic());
					PKCS10CertificationRequest csr =  csrBuilder.build(
							new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate()));

					DViewCsr dialog = new DViewCsr(new javax.swing.JFrame(), "Title", csr);
					dialog.addWindowListener(new java.awt.event.WindowAdapter() {
						@Override
						public void windowClosing(java.awt.event.WindowEvent e) {
							System.exit(0);
						}
					});
					dialog.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}
