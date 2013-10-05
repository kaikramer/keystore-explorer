/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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
package net.sf.keystore_explorer.gui.dialogs;

import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.KeyInfo;
import net.sf.keystore_explorer.crypto.csr.spkac.Spkac;
import net.sf.keystore_explorer.crypto.csr.spkac.SpkacSubject;
import net.sf.keystore_explorer.crypto.keypair.KeyPairUtil;
import net.sf.keystore_explorer.crypto.signing.SignatureType;
import net.sf.keystore_explorer.gui.CursorUtil;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.crypto.JDistinguishedName;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.asn1.Asn1Exception;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/**
 * Displays the details of a Certificate Signing Request (CSR).
 * 
 */
public class DViewCsr extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private JLabel jlFormat;
	private JTextField jtfFormat;
	private JLabel jlSubject;
	private JDistinguishedName jdnSubject;
	private JLabel jlPublicKey;
	private JPanel jpPublicKey;
	private JTextField jtfPublicKey;
	private JButton jbViewPublicKeyDetails;
	private JLabel jlSignatureAlgorithm;
	private JTextField jtfSignatureAlgorithm;
	private JLabel jlChallenge;
	private JTextField jtfChallenge;
	private JPanel jpCsr;
	private JPanel jpButtons;
	private JButton jbExtensions;
	private JButton jbPem;
	private JButton jbAsn1;
	private JPanel jpOK;
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
		super(parent, title, Dialog.ModalityType.APPLICATION_MODAL);
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
		super(parent, title, Dialog.ModalityType.APPLICATION_MODAL);
		this.spkacCsr = spkacCsr;
		initComponents();
	}

	private void initComponents() throws CryptoException {
		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 3;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;
		gbcLbl.weightx = 0;

		GridBagConstraints gbcCtrl = new GridBagConstraints();
		gbcCtrl.gridx = 3;
		gbcCtrl.gridwidth = 3;
		gbcCtrl.gridheight = 1;
		gbcCtrl.insets = new Insets(5, 5, 5, 5);
		gbcCtrl.anchor = GridBagConstraints.WEST;
		gbcCtrl.fill = GridBagConstraints.NONE;
		gbcCtrl.weightx = 1;

		jlFormat = new JLabel(res.getString("DViewCsr.jlFormat.text"));
		GridBagConstraints gbc_jlFormat = (GridBagConstraints) gbcLbl.clone();
		gbc_jlFormat.gridy = 0;

		jtfFormat = new JTextField(10);
		jtfFormat.setEditable(false);
		jtfFormat.setToolTipText(res.getString("DViewCsr.jtfFormat.tooltip"));
		GridBagConstraints gbc_jtfFormat = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfFormat.gridy = 0;

		jlSubject = new JLabel(res.getString("DViewCsr.jlSubject.text"));
		GridBagConstraints gbc_jlSubject = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSubject.gridy = 1;

		jdnSubject = new JDistinguishedName(res.getString("DViewCsr.Subject.Title"), 30, false);
		jdnSubject.setToolTipText(res.getString("DViewCsr.jdnSubject.tooltip"));
		GridBagConstraints gbc_jdnSubject = (GridBagConstraints) gbcCtrl.clone();
		gbc_jdnSubject.gridy = 1;

		jlPublicKey = new JLabel(res.getString("DViewCsr.jlPublicKey.text"));
		GridBagConstraints gbc_jlPublicKey = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPublicKey.gridy = 2;

		jtfPublicKey = new JTextField(15);
		jtfPublicKey.setEditable(false);
		jtfPublicKey.setToolTipText(res.getString("DViewCsr.jtfPublicKey.tooltip"));

		jbViewPublicKeyDetails = new JButton();
		jbViewPublicKeyDetails.setToolTipText(res.getString("DViewCsr.jbViewPublicKeyDetails.tooltip"));
		jbViewPublicKeyDetails.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("DViewCsr.jbViewPublicKeyDetails.image")))));
		jbViewPublicKeyDetails.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCsr.this);
					pubKeyDetailsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCsr.this);
				}
			}
		});

		jpPublicKey = new JPanel(new GridBagLayout());
		GridBagConstraints gbc_jpPublicKey = (GridBagConstraints) gbcCtrl.clone();
		gbc_jpPublicKey.gridy = 2;

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

		jlSignatureAlgorithm = new JLabel(res.getString("DViewCsr.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = 3;

		jtfSignatureAlgorithm = new JTextField(15);
		jtfSignatureAlgorithm.setEditable(false);
		jtfSignatureAlgorithm.setToolTipText(res.getString("DViewCsr.jtfSignatureAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfSignatureAlgorithm = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfSignatureAlgorithm.gridy = 3;

		jlChallenge = new JLabel(res.getString("DViewCsr.jlChallenge.text"));
		GridBagConstraints gbc_jlChallenge = (GridBagConstraints) gbcLbl.clone();
		gbc_jlChallenge.gridy = 4;

		jtfChallenge = new JTextField(15);
		jtfChallenge.setEditable(false);
		jtfChallenge.setToolTipText(res.getString("DViewCsr.jtfChallenge.tooltip"));
		GridBagConstraints gbc_jtfChallenge = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfChallenge.gridy = 4;

		jbExtensions = new JButton(res.getString("DViewCsr.jbExtensions.text"));

		PlatformUtil.setMnemonic(jbExtensions, res.getString("DViewCsr.jbExtensions.mnemonic").charAt(0));
		jbExtensions.setToolTipText(res.getString("DViewCsr.jbExtensions.tooltip"));
		jbExtensions.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCsr.this);
					// extensionsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCsr.this);
				}
			}
		});

		jbPem = new JButton(res.getString("DViewCsr.jbPem.text"));

		PlatformUtil.setMnemonic(jbPem, res.getString("DViewCsr.jbPem.mnemonic").charAt(0));
		jbPem.setToolTipText(res.getString("DViewCsr.jbPem.tooltip"));
		jbPem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCsr.this);
					pemEncodingPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCsr.this);
				}
			}
		});

		jbAsn1 = new JButton(res.getString("DViewCsr.jbAsn1.text"));

		PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewCsr.jbAsn1.mnemonic").charAt(0));
		jbAsn1.setToolTipText(res.getString("DViewCsr.jbAsn1.tooltip"));
		jbAsn1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCsr.this);
					asn1DumpPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCsr.this);
				}
			}
		});

		jpButtons = new JPanel();
		// jpButtons.add(jbExtensions); // TODO
		jpButtons.add(jbPem);
		jpButtons.add(jbAsn1);

		GridBagConstraints gbc_jpButtons = new GridBagConstraints();
		gbc_jpButtons.gridx = 2;
		gbc_jpButtons.gridy = 5;
		gbc_jpButtons.gridwidth = GridBagConstraints.REMAINDER;
		gbc_jpButtons.gridheight = 1;
		gbc_jpButtons.anchor = GridBagConstraints.EAST;

		jpCsr = new JPanel(new GridBagLayout());
		jpCsr.setBorder(new CompoundBorder(new EmptyBorder(10, 10, 10, 10), new EtchedBorder()));

		jpCsr.add(jlFormat, gbc_jlFormat);
		jpCsr.add(jtfFormat, gbc_jtfFormat);
		jpCsr.add(jlSubject, gbc_jlSubject);
		jpCsr.add(jdnSubject, gbc_jdnSubject);
		jpCsr.add(jlPublicKey, gbc_jlPublicKey);
		jpCsr.add(jpPublicKey, gbc_jpPublicKey);
		jpCsr.add(jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
		jpCsr.add(jtfSignatureAlgorithm, gbc_jtfSignatureAlgorithm);
		jpCsr.add(jlChallenge, gbc_jlChallenge);
		jpCsr.add(jtfChallenge, gbc_jtfChallenge);
		jpCsr.add(jpButtons, gbc_jpButtons);

		populateCsrDetails();

		jbOK = new JButton(res.getString("DViewCsr.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpOK = PlatformUtil.createDialogButtonPanel(jbOK, false);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpCsr, BorderLayout.NORTH);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
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

		jbExtensions.setEnabled(true);
		jbPem.setEnabled(true);
		jbAsn1.setEnabled(true);

		populatePublicKey(getPkcs10PublicKey());

		String sigAlgId = pkcs10Csr.getSignatureAlgorithm().getAlgorithm().getId();
		SignatureType sigAlg = SignatureType.resolveOid(sigAlgId);

		if (sigAlg != null) {
			jtfSignatureAlgorithm.setText(sigAlg.friendly());
		} else {
			jtfSignatureAlgorithm.setText(sigAlgId);
		}

		jtfSignatureAlgorithm.setCaretPosition(0);

		DialogHelper.populatePkcs10Challenge(pkcs10Csr.getAttributes(), jtfChallenge);
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

	private void pubKeyDetailsPressed() {
		try {
			PublicKey publicKey = null;

			if (pkcs10Csr != null) {
				publicKey = getPkcs10PublicKey();
			} else {
				publicKey = spkacCsr.getPublicKey();
			}

			DViewPublicKey dViewPublicKey = new DViewPublicKey(this, res.getString("DViewCsr.PubKeyDetails.Title"),
					APPLICATION_MODAL, publicKey);
			dViewPublicKey.setLocationRelativeTo(this);
			dViewPublicKey.setVisible(true);
		} catch (CryptoException ex) {
			DError dError = new DError(this, APPLICATION_MODAL, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
			return;
		}
	}

	private void pemEncodingPressed() {
		try {
			DViewCertCsrPem dViewCsrPem = new DViewCertCsrPem(this, res.getString("DViewCsr.Pem.Title"),
					APPLICATION_MODAL, pkcs10Csr);
			dViewCsrPem.setLocationRelativeTo(this);
			dViewCsrPem.setVisible(true);
		} catch (CryptoException ex) {
			DError dError = new DError(this, APPLICATION_MODAL, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
			return;
		}
	}

	private void asn1DumpPressed() {

		try {
			DViewAsn1Dump dViewAsn1Dump;
			if (pkcs10Csr != null) {
				dViewAsn1Dump = new DViewAsn1Dump(this, APPLICATION_MODAL, pkcs10Csr);
			} else {
				dViewAsn1Dump = new DViewAsn1Dump(this, APPLICATION_MODAL, spkacCsr);
			}
			dViewAsn1Dump.setLocationRelativeTo(this);
			dViewAsn1Dump.setVisible(true);
		} catch (Asn1Exception ex) {
			DError dError = new DError(this, APPLICATION_MODAL, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
			return;
		} catch (IOException ex) {
			DError dError = new DError(this, APPLICATION_MODAL, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
			return;
		}
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
