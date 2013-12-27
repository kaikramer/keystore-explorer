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
package net.sf.keystore_explorer.gui.dialogs.sign;

import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;
import static net.sf.keystore_explorer.crypto.x509.X509CertificateVersion.VERSION1;
import static net.sf.keystore_explorer.crypto.x509.X509CertificateVersion.VERSION3;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.KeyInfo;
import net.sf.keystore_explorer.crypto.csr.spkac.Spkac;
import net.sf.keystore_explorer.crypto.csr.spkac.SpkacSubject;
import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.crypto.keypair.KeyPairUtil;
import net.sf.keystore_explorer.crypto.signing.SignatureType;
import net.sf.keystore_explorer.crypto.x509.X500NameUtils;
import net.sf.keystore_explorer.crypto.x509.X509CertificateVersion;
import net.sf.keystore_explorer.crypto.x509.X509ExtensionSet;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.CursorUtil;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.crypto.JDistinguishedName;
import net.sf.keystore_explorer.gui.crypto.JValidityPeriod;
import net.sf.keystore_explorer.gui.dialogs.DViewPublicKey;
import net.sf.keystore_explorer.gui.dialogs.DialogHelper;
import net.sf.keystore_explorer.gui.dialogs.extensions.DAddExtensions;
import net.sf.keystore_explorer.gui.error.DError;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/**
 * Dialog that displays the details of a CSR and presents signing options for
 * it.
 * 
 */
public class DSignCsr extends JEscDialog {
	private static ResourceBundle res = ResourceBundle
			.getBundle("net/sf/keystore_explorer/gui/dialogs/sign/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlCsrFormat;
	private JTextField jtfCsrFormat;
	private JLabel jlCsrSubject;
	private JDistinguishedName jdnCsrSubject;
	private JLabel jlCsrPublicKey;
	private JPanel jpCsrPublicKey;
	private JTextField jtfCsrPublicKey;
	private JButton jbViewCsrPublicKeyDetails;
	private JLabel jlCsrSignatureAlgorithm;
	private JTextField jtfCsrSignatureAlgorithm;
	private JLabel jlCsrChallenge;
	private JTextField jtfCsrChallenge;
	private JPanel jpCsrDetails;
	private JLabel jlVersion;
	private JPanel jpVersions;
	private JRadioButton jrbVersion1;
	private JRadioButton jrbVersion3;
	private JLabel jlSignatureAlgorithm;
	private JComboBox jcbSignatureAlgorithm;
	private JLabel jlValidityPeriod;
	private JValidityPeriod jvpValidityPeriod;
	private JLabel jlSerialNumber;
	private JTextField jtfSerialNumber;
	private JLabel jlCaReplyFile;
	private JTextField jtfCaReplyFile;
	private JButton jbBrowse;
	private JButton jbAddExtensions;
	private JPanel jpSigningOptions;
	private JPanel jpOptions;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private PrivateKey signPrivateKey;
	private KeyPairType signKeyPairType;
	private X509Certificate verificationCertificate;
	private PKCS10CertificationRequest pkcs10Csr;
	private Spkac spkacCsr;
	private PublicKey csrPublicKey;
	private X509CertificateVersion version;
	private SignatureType signatureType;
	private long validityPeriod;
	private BigInteger serialNumber;
	private File caReplyFile;
	private X509ExtensionSet extensions = new X509ExtensionSet();

	/**
	 * Creates a new DSignCsr dialog for a PKCS #10 formatted CSR.
	 * 
	 * @param parent
	 *            The parent frame
	 * @param pkcs10Csr
	 *            The PKCS #10 formatted CSR
	 * @param signPrivateKey
	 *            Signing private key
	 * @param signKeyPairType
	 *            Signing key pair's type
	 * @param verificationCertificate
	 *            Verification certificate
	 * @throws CryptoException
	 *             A crypto problem was encountered constructing the dialog
	 */
	public DSignCsr(JFrame parent, PKCS10CertificationRequest pkcs10Csr, PrivateKey signPrivateKey,
			KeyPairType signKeyPairType, X509Certificate verificationCertificate) throws CryptoException {
		super(parent, Dialog.ModalityType.APPLICATION_MODAL);
		this.pkcs10Csr = pkcs10Csr;
		this.signPrivateKey = signPrivateKey;
		this.signKeyPairType = signKeyPairType;
		this.verificationCertificate = verificationCertificate;
		setTitle(res.getString("DSignCsr.Title"));
		initComponents();
	}

	/**
	 * Creates a new DSignCsr dialog for a SPKAC formatted CSR.
	 * 
	 * @param parent
	 *            The parent frame
	 * @param spkacCsr
	 *            The SPKAC formatted CSR
	 * @param signPrivateKey
	 *            Signing private key
	 * @param signKeyPairType
	 *            Signing key pair's type
	 * @param verificationCertificate
	 *            Verification certificate
	 * @throws CryptoException
	 *             A crypto problem was encountered constructing the dialog
	 */
	public DSignCsr(JFrame parent, Spkac spkacCsr, PrivateKey signPrivateKey, KeyPairType signKeyPairType,
			X509Certificate verificationCertificate) throws CryptoException {
		super(parent, Dialog.ModalityType.APPLICATION_MODAL);
		this.spkacCsr = spkacCsr;
		this.signPrivateKey = signPrivateKey;
		this.signKeyPairType = signKeyPairType;
		this.verificationCertificate = verificationCertificate;
		setTitle(res.getString("DSignCsr.Title"));
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

		jlCsrFormat = new JLabel(res.getString("DSignCsr.jlCsrFormat.text"));
		GridBagConstraints gbc_jlCsrFormat = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCsrFormat.gridy = 0;

		jtfCsrFormat = new JTextField(10);
		jtfCsrFormat.setEditable(false);
		jtfCsrFormat.setToolTipText(res.getString("DSignCsr.jtfCsrFormat.tooltip"));
		GridBagConstraints gbc_jtfCsrFormat = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfCsrFormat.gridy = 0;

		jlCsrSubject = new JLabel(res.getString("DSignCsr.jlCsrSubject.text"));
		GridBagConstraints gbc_jlCsrSubject = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCsrSubject.gridy = 1;

		jdnCsrSubject = new JDistinguishedName(res.getString("DSignCsr.Subject.Title"), 30, false);
		jdnCsrSubject.setToolTipText(res.getString("DSignCsr.jdnCsrSubject.tooltip"));
		GridBagConstraints gbc_jdnCsrSubject = (GridBagConstraints) gbcCtrl.clone();
		gbc_jdnCsrSubject.gridy = 1;

		jlCsrPublicKey = new JLabel(res.getString("DSignCsr.jlCsrPublicKey.text"));
		GridBagConstraints gbc_jlCsrPublicKey = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCsrPublicKey.gridy = 2;

		jtfCsrPublicKey = new JTextField(15);
		jtfCsrPublicKey.setEditable(false);
		jtfCsrPublicKey.setToolTipText(res.getString("DSignCsr.jtfCsrPublicKey.tooltip"));

		jbViewCsrPublicKeyDetails = new JButton();
		jbViewCsrPublicKeyDetails.setToolTipText(res.getString("DSignCsr.jbViewCsrPublicKeyDetails.tooltip"));
		jbViewCsrPublicKeyDetails.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("DSignCsr.jbViewCsrPublicKeyDetails.image")))));
		jbViewCsrPublicKeyDetails.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignCsr.this);
					pubKeyDetailsPressed();
				} finally {
					CursorUtil.setCursorFree(DSignCsr.this);
				}
			}
		});

		jpCsrPublicKey = new JPanel(new GridBagLayout());
		GridBagConstraints gbc_jpCsrPublicKey = (GridBagConstraints) gbcCtrl.clone();
		gbc_jpCsrPublicKey.gridy = 2;

		GridBagConstraints gbc_jtfCsrPublicKey = new GridBagConstraints();
		gbc_jtfCsrPublicKey.gridwidth = 1;
		gbc_jtfCsrPublicKey.gridheight = 1;
		gbc_jtfCsrPublicKey.gridx = 0;
		gbc_jtfCsrPublicKey.gridy = 0;
		gbc_jtfCsrPublicKey.insets = new Insets(0, 0, 0, 5);

		GridBagConstraints gbc_jbViewCsrPublicKeyDetails = new GridBagConstraints();
		gbc_jbViewCsrPublicKeyDetails.gridwidth = 1;
		gbc_jbViewCsrPublicKeyDetails.gridheight = 1;
		gbc_jbViewCsrPublicKeyDetails.gridx = 1;
		gbc_jbViewCsrPublicKeyDetails.gridy = 0;
		gbc_jbViewCsrPublicKeyDetails.insets = new Insets(0, 5, 0, 0);

		jpCsrPublicKey.add(jtfCsrPublicKey, gbc_jtfCsrPublicKey);
		jpCsrPublicKey.add(jbViewCsrPublicKeyDetails, gbc_jbViewCsrPublicKeyDetails);

		jlCsrSignatureAlgorithm = new JLabel(res.getString("DSignCsr.jlCsrSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlCsrSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCsrSignatureAlgorithm.gridy = 3;

		jtfCsrSignatureAlgorithm = new JTextField(15);
		jtfCsrSignatureAlgorithm.setEditable(false);
		jtfCsrSignatureAlgorithm.setToolTipText(res.getString("DSignCsr.jtfCsrSignatureAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfCsrSignatureAlgorithm = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfCsrSignatureAlgorithm.gridy = 3;

		jlCsrChallenge = new JLabel(res.getString("DSignCsr.jlCsrChallenge.text"));
		GridBagConstraints gbc_jlCsrChallenge = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCsrChallenge.gridy = 4;

		jtfCsrChallenge = new JTextField(15);
		jtfCsrChallenge.setEditable(false);
		jtfCsrChallenge.setToolTipText(res.getString("DSignCsr.jtfCsrChallenge.tooltip"));
		GridBagConstraints gbc_jtfCsrChallenge = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfCsrChallenge.gridy = 4;

		jpCsrDetails = new JPanel(new GridBagLayout());
		jpCsrDetails.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new TitledBorder(new EtchedBorder(), res
				.getString("DSignCsr.jpCsrDetails.text"))));

		jpCsrDetails.add(jlCsrFormat, gbc_jlCsrFormat);
		jpCsrDetails.add(jtfCsrFormat, gbc_jtfCsrFormat);
		jpCsrDetails.add(jlCsrSubject, gbc_jlCsrSubject);
		jpCsrDetails.add(jdnCsrSubject, gbc_jdnCsrSubject);
		jpCsrDetails.add(jlCsrPublicKey, gbc_jlCsrPublicKey);
		jpCsrDetails.add(jpCsrPublicKey, gbc_jpCsrPublicKey);
		jpCsrDetails.add(jlCsrSignatureAlgorithm, gbc_jlCsrSignatureAlgorithm);
		jpCsrDetails.add(jtfCsrSignatureAlgorithm, gbc_jtfCsrSignatureAlgorithm);
		jpCsrDetails.add(jlCsrChallenge, gbc_jlCsrChallenge);
		jpCsrDetails.add(jtfCsrChallenge, gbc_jtfCsrChallenge);

		populateCsrDetails();

		jlVersion = new JLabel(res.getString("DSignCsr.jlVersion.text"));
		GridBagConstraints gbc_jlVersion = (GridBagConstraints) gbcLbl.clone();
		gbc_jlVersion.gridy = 0;

		jrbVersion1 = new JRadioButton(res.getString("DSignCsr.jrbVersion1.text"));
		jrbVersion1.setToolTipText(res.getString("DSignCsr.jrbVersion1.tooltip"));

		jrbVersion3 = new JRadioButton(res.getString("DSignCsr.jrbVersion3.text"));
		jrbVersion3.setToolTipText(res.getString("DSignCsr.jrbVersion3.tooltip"));

		jpVersions = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
		GridBagConstraints gbc_jpVersions = (GridBagConstraints) gbcCtrl.clone();
		gbc_jpVersions.gridx = 4;
		gbc_jpVersions.gridy = 0;

		jpVersions.add(jrbVersion1);
		jpVersions.add(jrbVersion3);

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbVersion1);
		buttonGroup.add(jrbVersion3);

		jlSignatureAlgorithm = new JLabel(res.getString("DSignCsr.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = 1;

		jcbSignatureAlgorithm = new JComboBox();
		jcbSignatureAlgorithm.setMaximumRowCount(10);
		DialogHelper.populateSigAlgs(signKeyPairType, this.signPrivateKey, jcbSignatureAlgorithm);
		jcbSignatureAlgorithm.setToolTipText(res.getString("DSignCsr.jcbSignatureAlgorithm.tooltip"));
		GridBagConstraints gbc_jcbSignatureAlgorithm = (GridBagConstraints) gbcCtrl.clone();
		gbc_jcbSignatureAlgorithm.gridy = 1;

		jlValidityPeriod = new JLabel(res.getString("DSignCsr.jlValidityPeriod.text"));
		GridBagConstraints gbc_jlValidityPeriod = (GridBagConstraints) gbcLbl.clone();
		gbc_jlValidityPeriod.gridy = 2;

		jvpValidityPeriod = new JValidityPeriod(JValidityPeriod.YEARS);
		jvpValidityPeriod.setToolTipText(res.getString("DSignCsr.jvpValidityPeriod.tooltip"));
		GridBagConstraints gbc_jvpValidityPeriod = (GridBagConstraints) gbcCtrl.clone();
		gbc_jvpValidityPeriod.gridy = 2;

		jlSerialNumber = new JLabel(res.getString("DSignCsr.jlSerialNumber.text"));
		GridBagConstraints gbc_jlSerialNumber = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSerialNumber.gridy = 3;

		jtfSerialNumber = new JTextField("" + generateSerialNumber(), 10);
		jtfSerialNumber.setToolTipText(res.getString("DSignCsr.jtfSerialNumber.tooltip"));
		GridBagConstraints gbc_jtfSerialNumber = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfSerialNumber.gridy = 3;

		jpSigningOptions = new JPanel(new GridBagLayout());
		jpSigningOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new TitledBorder(new EtchedBorder(),
				res.getString("DSignCsr.jpSigningOptions.text"))));

		jlCaReplyFile = new JLabel(res.getString("DSignCsr.jlCaReplyFile.text"));
		GridBagConstraints gbc_jlCaReplyFile = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCaReplyFile.gridy = 4;

		jtfCaReplyFile = new JTextField(30);
		jtfCaReplyFile.setToolTipText(res.getString("DSignCsr.jtfCaReplyFile.tooltip"));
		GridBagConstraints gbc_jtfCaReplyFile = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfCaReplyFile.gridy = 4;
		gbc_jtfCaReplyFile.gridwidth = 9;
		gbc_jtfCaReplyFile.fill = GridBagConstraints.HORIZONTAL;

		jbBrowse = new JButton(res.getString("DSignCsr.jbBrowse.text"));
		jbBrowse.setToolTipText(res.getString("DSignCsr.jbBrowse.tooltip"));
		PlatformUtil.setMnemonic(jbBrowse, res.getString("DSignCsr.jbBrowse.mnemonic").charAt(0));
		GridBagConstraints gbc_jbBrowse = (GridBagConstraints) gbcCtrl.clone();
		gbc_jbBrowse.gridy = 4;
		gbc_jbBrowse.gridx = 12;
		gbc_jbBrowse.gridwidth = 3;
		gbc_jbBrowse.fill = GridBagConstraints.HORIZONTAL;

		jbBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignCsr.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DSignCsr.this);
				}
			}
		});

		jbAddExtensions = new JButton(res.getString("DSignCsr.jbAddExtensions.text"));
		jbAddExtensions.setMnemonic(res.getString("DSignCsr.jbAddExtensions.mnemonic").charAt(0));
		jbAddExtensions.setToolTipText(res.getString("DSignCsr.jbAddExtensions.tooltip"));
		GridBagConstraints gbc_jbAddExtensions = (GridBagConstraints) gbcCtrl.clone();
		gbc_jbAddExtensions.gridy = 5;
		gbc_jbAddExtensions.gridwidth = 15;
		gbc_jbAddExtensions.anchor = GridBagConstraints.EAST;

		jbAddExtensions.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignCsr.this);
					addExtensionsPressed();
				} finally {
					CursorUtil.setCursorFree(DSignCsr.this);
				}
			}
		});

		jrbVersion3.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent evt) {
				jbAddExtensions.setEnabled(jrbVersion3.isSelected());
			}
		});

		jrbVersion3.setSelected(true);

		jpSigningOptions.add(jlVersion, gbc_jlVersion);
		jpSigningOptions.add(jpVersions, gbc_jpVersions);
		jpSigningOptions.add(jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
		jpSigningOptions.add(jcbSignatureAlgorithm, gbc_jcbSignatureAlgorithm);
		jpSigningOptions.add(jlValidityPeriod, gbc_jlValidityPeriod);
		jpSigningOptions.add(jvpValidityPeriod, gbc_jvpValidityPeriod);
		jpSigningOptions.add(jlSerialNumber, gbc_jlSerialNumber);
		jpSigningOptions.add(jtfSerialNumber, gbc_jtfSerialNumber);
		jpSigningOptions.add(jlCaReplyFile, gbc_jlCaReplyFile);
		jpSigningOptions.add(jtfCaReplyFile, gbc_jtfCaReplyFile);
		jpSigningOptions.add(jbBrowse, gbc_jbBrowse);
		jpSigningOptions.add(jbAddExtensions, gbc_jbAddExtensions);

		jpOptions = new JPanel(new BorderLayout());
		jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpOptions.add(jpCsrDetails, BorderLayout.NORTH);
		jpOptions.add(jpSigningOptions, BorderLayout.SOUTH);

		jbOK = new JButton(res.getString("DSignCsr.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DSignCsr.jbCancel.text"));
		jbCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpOptions, BorderLayout.NORTH);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

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
		jtfCsrFormat.setText(res.getString("DSignCsr.jtfCsrFormat.Pkcs10.text"));
		jtfCsrFormat.setCaretPosition(0);

		jdnCsrSubject.setDistinguishedName(pkcs10Csr.getSubject());

		try {
			csrPublicKey = new JcaPKCS10CertificationRequest(pkcs10Csr).getPublicKey();
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("DSignCsr.NoGetCsrPublicKey.message"), ex);
		}

		populatePublicKey();

		String sigAlgId = pkcs10Csr.getSignatureAlgorithm().getAlgorithm().getId();
		SignatureType sigAlg = SignatureType.resolveOid(sigAlgId);

		if (sigAlg != null) {
			jtfCsrSignatureAlgorithm.setText(sigAlg.friendly());
		} else {
			jtfCsrSignatureAlgorithm.setText(sigAlgId);
		}

		jtfCsrSignatureAlgorithm.setCaretPosition(0);

		DialogHelper.populatePkcs10Challenge(pkcs10Csr.getAttributes(), jtfCsrChallenge);
	}


	private void populateSpkacCsrDetails() throws CryptoException {
		jtfCsrFormat.setText(res.getString("DSignCsr.jtfCsrFormat.Spkac.text"));
		jtfCsrFormat.setCaretPosition(0);

		SpkacSubject subject = spkacCsr.getSubject();
		jdnCsrSubject.setDistinguishedName(subject.getName());

		csrPublicKey = spkacCsr.getPublicKey();
		populatePublicKey();

		jtfCsrSignatureAlgorithm.setText(spkacCsr.getSignatureAlgorithm().friendly());
		jtfCsrSignatureAlgorithm.setCaretPosition(0);

		jtfCsrChallenge.setText(spkacCsr.getChallenge());
		jtfCsrChallenge.setCaretPosition(0);
	}

	private void populatePublicKey() throws CryptoException {
		KeyInfo keyInfo = KeyPairUtil.getKeyInfo(csrPublicKey);

		jtfCsrPublicKey.setText(keyInfo.getAlgorithm());
		Integer keySize = keyInfo.getSize();

		if (keySize != null) {
			jtfCsrPublicKey.setText(MessageFormat.format(res.getString("DSignCsr.jtfCsrPublicKey.text"),
					jtfCsrPublicKey.getText(), "" + keySize));
		} else {
			jtfCsrPublicKey.setText(MessageFormat.format(res.getString("DSignCsr.jtfCsrPublicKey.text"),
					jtfCsrPublicKey.getText(), "?"));
		}

		jtfCsrPublicKey.setCaretPosition(0);
	}

	private long generateSerialNumber() {
		return System.currentTimeMillis() / 1000;
	}

	private void addExtensionsPressed() {
		DAddExtensions dAddExtensions = new DAddExtensions(this, extensions, verificationCertificate.getPublicKey(),
				X500NameUtils.x500PrincipalToX500Name(verificationCertificate.getSubjectX500Principal()),
				verificationCertificate.getSerialNumber(), csrPublicKey);
		dAddExtensions.setLocationRelativeTo(this);
		dAddExtensions.setVisible(true);

		if (dAddExtensions.getExtensions() != null) {
			// Dialog not cancelled
			extensions = dAddExtensions.getExtensions();
		}
	}

	/**
	 * Get chosen certificate version.
	 * 
	 * @return Certificate version or null if dialog cancelled
	 */
	public X509CertificateVersion getVersion() {
		return version;
	}

	/**
	 * Get chosen signature type.
	 * 
	 * @return Signature type or null if dialog cancelled
	 */
	public SignatureType getSignatureType() {
		return signatureType;
	}

	/**
	 * Get chosen validity period.
	 * 
	 * @return Validity period or -1 if dialog cancelled
	 */
	public long getValidityPeriod() {
		return validityPeriod;
	}

	/**
	 * Get chosen serial number.
	 * 
	 * @return Serial number or null if dialog cancelled
	 */
	public BigInteger getSerialNumber() {
		return serialNumber;
	}

	/**
	 * Get chosen CA Reply file.
	 * 
	 * @return CA Reply file or null if dialog cancelled
	 */
	public File getCaReplyFile() {
		return caReplyFile;
	}

	/**
	 * Get chosen certficate extensions.
	 * 
	 * @return Certificate extensions or null if dialog cancelled.
	 */
	public X509ExtensionSet getExtensions() {
		return extensions;
	}

	private void browsePressed() {
		JFileChooser chooser = FileChooserFactory.getCaReplyFileChooser();

		File currentExportFile = new File(jtfCaReplyFile.getText().trim());

		if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentExportFile.getParentFile());
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DSignCsr.SaveCaReply.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DSignCsr.SaveCaReply.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfCaReplyFile.setText(chosenFile.toString());
			jtfCaReplyFile.setCaretPosition(0);
		}
	}

	private void pubKeyDetailsPressed() {
		try {
			DViewPublicKey dViewPublicKey = new DViewPublicKey(this, res.getString("DSignCsr.PubKeyDetails.Title"),
					APPLICATION_MODAL, csrPublicKey);
			dViewPublicKey.setLocationRelativeTo(this);
			dViewPublicKey.setVisible(true);
		} catch (CryptoException ex) {
			DError dError = new DError(this, APPLICATION_MODAL, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
			return;
		}
	}

	private void okPressed() {
		String serialNumberStr = jtfSerialNumber.getText().trim();
		if (serialNumberStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DSignCsr.ValReqSerialNumber.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}
		long serialNumberLong;
		try {
			serialNumberLong = Integer.parseInt(serialNumberStr);
			if (serialNumberLong < 0) {
				JOptionPane.showMessageDialog(this, res.getString("DSignCsr.SerialNumberNonZero.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}
		} catch (NumberFormatException ex) {
			JOptionPane.showMessageDialog(this, res.getString("DSignCsr.SerialNumberNotInteger.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		String exportFileStr = jtfCaReplyFile.getText().trim();

		if (exportFileStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DSignCsr.CaReplyFileRequired.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		File caReplyFile = new File(exportFileStr);

		if (caReplyFile.isFile()) {
			String message = MessageFormat.format(res.getString("DSignCsr.OverWriteCaReplyFile.message"), caReplyFile);

			int selected = JOptionPane.showConfirmDialog(this, message, getTitle(), JOptionPane.YES_NO_OPTION);
			if (selected != JOptionPane.YES_OPTION) {
				return;
			}
		}

		this.caReplyFile = caReplyFile;

		if (jrbVersion1.isSelected()) {
			version = VERSION1;
			extensions = null;
		} else {
			version = VERSION3;
		}

		signatureType = (SignatureType) jcbSignatureAlgorithm.getSelectedItem();
		validityPeriod = jvpValidityPeriod.getValidityPeriodMs();
		serialNumber = BigInteger.valueOf(serialNumberLong);

		closeDialog();
	}

	private void cancelPressed() {
		extensions = null;
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
