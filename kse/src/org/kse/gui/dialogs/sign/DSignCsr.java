/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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
package org.kse.gui.dialogs.sign;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;
import static org.kse.crypto.x509.X509CertificateVersion.VERSION1;
import static org.kse.crypto.x509.X509CertificateVersion.VERSION3;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Date;
import java.util.ResourceBundle;
import java.util.concurrent.TimeUnit;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.csr.pkcs10.Pkcs10Util;
import org.kse.crypto.csr.spkac.Spkac;
import org.kse.crypto.csr.spkac.SpkacSubject;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.crypto.x509.X509CertificateVersion;
import org.kse.crypto.x509.X509ExtensionSet;
import org.kse.crypto.x509.X509ExtensionSetUpdater;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.MiGUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.crypto.JValidityPeriod;
import org.kse.gui.datetime.JDateTime;
import org.kse.gui.dialogs.DViewAsn1Dump;
import org.kse.gui.dialogs.DViewPem;
import org.kse.gui.dialogs.DViewPublicKey;
import org.kse.gui.dialogs.DialogHelper;
import org.kse.gui.dialogs.extensions.DAddExtensions;
import org.kse.gui.dialogs.extensions.DViewExtensions;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.SerialNumbers;
import org.kse.utilities.asn1.Asn1Exception;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that displays the details of a CSR and presents signing options for
 * it.
 */
public class DSignCsr extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlCsrFormat;
    private JTextField jtfCsrFormat;
    private JLabel jlCsrSubject;
    private JDistinguishedName jdnCsrSubject;
    private JLabel jlCsrPublicKey;
    private JTextField jtfCsrPublicKey;
    private JButton jbViewCsrPublicKeyDetails;
    private JLabel jlCsrSignatureAlgorithm;
    private JTextField jtfCsrSignatureAlgorithm;
    private JLabel jlCsrChallenge;
    private JTextField jtfCsrChallenge;
    private JButton jbCsrExtensions;
    private JButton jbCsrPem;
    private JButton jbCsrAsn1;

    private JLabel jlVersion;
    private JRadioButton jrbVersion1;
    private JRadioButton jrbVersion3;
    private JLabel jlSignatureAlgorithm;
    private JComboBox<SignatureType> jcbSignatureAlgorithm;
    private JLabel jlSubjectDN;
    private JDistinguishedName jdnSubjectDN;
    private JLabel jlValidityStart;
    private JDateTime jdtValidityStart;
    private JLabel jlValidityEnd;
    private JDateTime jdtValidityEnd;
    private JLabel jlValidityPeriod;
    private JValidityPeriod jvpValidityPeriod;
    private JLabel jlSerialNumber;
    private JTextField jtfSerialNumber;
    private JButton jbTransferExtensions;
    private JButton jbAddExtensions;
    private JButton jbOK;
    private JButton jbCancel;

    private PrivateKey signPrivateKey;
    private KeyPairType signKeyPairType;
    private X509Certificate issuerCertificate;
    private PKCS10CertificationRequest pkcs10Csr;
    private Spkac spkacCsr;
    private PublicKey csrPublicKey;
    private X509CertificateVersion version;
    private SignatureType signatureType;
    private Date validityStart;
    private Date validityEnd;
    private BigInteger serialNumber;
    private X500Name subjectDN;
    private X509ExtensionSet extensions = new X509ExtensionSet();

    /**
     * Creates a new DSignCsr dialog for a PKCS #10 formatted CSR.
     *
     * @param parent            The parent frame
     * @param pkcs10Csr         The PKCS #10 formatted CSR
     * @param signPrivateKey    Signing private key
     * @param signKeyPairType   Signing key pair's type
     * @param issuerCertificate Issuer certificate
     * @throws CryptoException A crypto problem was encountered constructing the dialog
     */
    public DSignCsr(JFrame parent, PKCS10CertificationRequest pkcs10Csr, PrivateKey signPrivateKey,
                    KeyPairType signKeyPairType, X509Certificate issuerCertificate) throws CryptoException {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.pkcs10Csr = pkcs10Csr;
        this.signPrivateKey = signPrivateKey;
        this.signKeyPairType = signKeyPairType;
        this.issuerCertificate = issuerCertificate;
        setTitle(res.getString("DSignCsr.Title"));
        initComponents();
    }

    /**
     * Creates a new DSignCsr dialog for a SPKAC formatted CSR.
     *
     * @param parent            The parent frame
     * @param spkacCsr          The SPKAC formatted CSR
     * @param signPrivateKey    Signing private key
     * @param signKeyPairType   Signing key pair's type
     * @param issuerCertificate Issuer certificate
     * @throws CryptoException A crypto problem was encountered constructing the dialog
     */
    public DSignCsr(JFrame parent, Spkac spkacCsr, PrivateKey signPrivateKey, KeyPairType signKeyPairType,
                    X509Certificate issuerCertificate) throws CryptoException {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.spkacCsr = spkacCsr;
        this.signPrivateKey = signPrivateKey;
        this.signKeyPairType = signKeyPairType;
        this.issuerCertificate = issuerCertificate;
        setTitle(res.getString("DSignCsr.Title"));
        initComponents();
    }

    private void initComponents() throws CryptoException {

        jlCsrFormat = new JLabel(res.getString("DSignCsr.jlCsrFormat.text"));

        jtfCsrFormat = new JTextField(40);
        jtfCsrFormat.setEditable(false);
        jtfCsrFormat.setToolTipText(res.getString("DSignCsr.jtfCsrFormat.tooltip"));

        jlCsrSubject = new JLabel(res.getString("DSignCsr.jlCsrSubject.text"));

        jdnCsrSubject = new JDistinguishedName(res.getString("DSignCsr.Subject.Title"), 40, false);
        jdnCsrSubject.setToolTipText(res.getString("DSignCsr.jdnCsrSubject.tooltip"));

        jlCsrPublicKey = new JLabel(res.getString("DSignCsr.jlCsrPublicKey.text"));

        jtfCsrPublicKey = new JTextField(40);
        jtfCsrPublicKey.setEditable(false);
        jtfCsrPublicKey.setToolTipText(res.getString("DSignCsr.jtfCsrPublicKey.tooltip"));

        jbViewCsrPublicKeyDetails = new JButton();
        jbViewCsrPublicKeyDetails.setToolTipText(res.getString("DSignCsr.jbViewCsrPublicKeyDetails.tooltip"));
        jbViewCsrPublicKeyDetails.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/viewpubkey.png"))));

        jlCsrSignatureAlgorithm = new JLabel(res.getString("DSignCsr.jlCsrSignatureAlgorithm.text"));

        jtfCsrSignatureAlgorithm = new JTextField(40);
        jtfCsrSignatureAlgorithm.setEditable(false);
        jtfCsrSignatureAlgorithm.setToolTipText(res.getString("DSignCsr.jtfCsrSignatureAlgorithm.tooltip"));

        jlCsrChallenge = new JLabel(res.getString("DSignCsr.jlCsrChallenge.text"));

        jtfCsrChallenge = new JTextField(40);
        jtfCsrChallenge.setEditable(false);
        jtfCsrChallenge.setToolTipText(res.getString("DSignCsr.jtfCsrChallenge.tooltip"));

        jbCsrExtensions = new JButton(res.getString("DSignCsr.jbCsrExtensions.text"));
        PlatformUtil.setMnemonic(jbCsrExtensions, res.getString("DSignCsr.jbCsrExtensions.mnemonic").charAt(0));
        jbCsrExtensions.setToolTipText(res.getString("DSignCsr.jbCsrExtensions.tooltip"));

        jbCsrPem = new JButton(res.getString("DSignCsr.jbCsrPem.text"));
        PlatformUtil.setMnemonic(jbCsrPem, res.getString("DSignCsr.jbCsrPem.mnemonic").charAt(0));
        jbCsrPem.setToolTipText(res.getString("DSignCsr.jbCsrPem.tooltip"));

        jbCsrAsn1 = new JButton(res.getString("DSignCsr.jbCsrAsn1.text"));
        PlatformUtil.setMnemonic(jbCsrAsn1, res.getString("DSignCsr.jbCsrAsn1.mnemonic").charAt(0));
        jbCsrAsn1.setToolTipText(res.getString("DSignCsr.jbCsrAsn1.tooltip"));

        jlVersion = new JLabel(res.getString("DSignCsr.jlVersion.text"));

        jrbVersion1 = new JRadioButton(res.getString("DSignCsr.jrbVersion1.text"));
        jrbVersion1.setToolTipText(res.getString("DSignCsr.jrbVersion1.tooltip"));

        jrbVersion3 = new JRadioButton(res.getString("DSignCsr.jrbVersion3.text"));
        jrbVersion3.setToolTipText(res.getString("DSignCsr.jrbVersion3.tooltip"));

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(jrbVersion1);
        buttonGroup.add(jrbVersion3);
        jrbVersion3.setSelected(true);

        jlSignatureAlgorithm = new JLabel(res.getString("DSignCsr.jlSignatureAlgorithm.text"));

        jcbSignatureAlgorithm = new JComboBox<>();
        jcbSignatureAlgorithm.setMaximumRowCount(10);
        DialogHelper.populateSigAlgs(signKeyPairType, this.signPrivateKey, jcbSignatureAlgorithm);
        jcbSignatureAlgorithm.setToolTipText(res.getString("DSignCsr.jcbSignatureAlgorithm.tooltip"));

        jlSubjectDN = new JLabel(res.getString("DSignCsr.jlCsrSubject.text"));

        jdnSubjectDN = new JDistinguishedName(res.getString("DSignCsr.Subject.Title"), 40, true);
        jdnSubjectDN.setToolTipText(res.getString("DSignCsr.jdnCsrSubject.tooltip"));

        Date now = new Date();

        jlValidityStart = new JLabel(res.getString("DSignCsr.jlValidityStart.text"));

        jdtValidityStart = new JDateTime(res.getString("DSignCsr.jdtValidityStart.text"), false);
        jdtValidityStart.setDateTime(now);
        jdtValidityStart.setToolTipText(res.getString("DSignCsr.jdtValidityStart.tooltip"));

        jlValidityEnd = new JLabel(res.getString("DSignCsr.jlValidityEnd.text"));

        jdtValidityEnd = new JDateTime(res.getString("DSignCsr.jdtValidityEnd.text"), false);
        jdtValidityEnd.setDateTime(new Date(now.getTime() + TimeUnit.DAYS.toMillis(365)));
        jdtValidityEnd.setToolTipText(res.getString("DSignCsr.jdtValidityEnd.tooltip"));

        jlValidityPeriod = new JLabel(res.getString("DSignCsr.jlValidityPeriod.text"));

        jvpValidityPeriod = new JValidityPeriod(JValidityPeriod.YEARS);
        jvpValidityPeriod.setToolTipText(res.getString("DSignCsr.jvpValidityPeriod.tooltip"));

        jlSerialNumber = new JLabel(res.getString("DSignCsr.jlSerialNumber.text"));

        jtfSerialNumber = new JTextField(X509CertUtil.generateCertSerialNumber(), 40);
        jtfSerialNumber.setToolTipText(res.getString("DSignCsr.jtfSerialNumber.tooltip"));

        jbTransferExtensions = new JButton(res.getString("DSignCsr.jbTransferExtensions.text"));
        jbTransferExtensions.setMnemonic(res.getString("DSignCsr.jbTransferExtensions.mnemonic").charAt(0));
        jbTransferExtensions.setToolTipText(res.getString("DSignCsr.jbTransferExtensions.tooltip"));

        jbAddExtensions = new JButton(res.getString("DSignCsr.jbAddExtensions.text"));
        jbAddExtensions.setMnemonic(res.getString("DSignCsr.jbAddExtensions.mnemonic").charAt(0));
        jbAddExtensions.setToolTipText(res.getString("DSignCsr.jbAddExtensions.tooltip"));

        jbOK = new JButton(res.getString("DSignCsr.jbOK.text"));
        jbCancel = new JButton(res.getString("DSignCsr.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
        MiGUtil.addSeparator(pane, res.getString("DSignCsr.jpCsrDetails.text"));
        pane.add(jlCsrFormat, "");
        pane.add(jtfCsrFormat, "wrap");
        pane.add(jlCsrSubject, "");
        pane.add(jdnCsrSubject, "wrap");
        pane.add(jlCsrPublicKey, "");
        pane.add(jtfCsrPublicKey, "split 2");
        pane.add(jbViewCsrPublicKeyDetails, "gapx 5px, wrap"); // TODO change gap after JDistinguishedName has been migrated
        pane.add(jlCsrSignatureAlgorithm, "");
        pane.add(jtfCsrSignatureAlgorithm, "wrap");
        pane.add(jlCsrChallenge, "");
        pane.add(jtfCsrChallenge, "wrap");
        pane.add(jbCsrExtensions, "right, spanx, split");
        pane.add(jbCsrPem, "");
        pane.add(jbCsrAsn1, "wrap");
        MiGUtil.addSeparator(pane, res.getString("DSignCsr.jpSigningOptions.text"));
        pane.add(jlVersion, "");
        pane.add(jrbVersion1, "split 2");
        pane.add(jrbVersion3, "wrap");
        pane.add(jlSignatureAlgorithm, "");
        pane.add(jcbSignatureAlgorithm, "wrap");
        pane.add(jlSubjectDN, "");
        pane.add(jdnSubjectDN, "wrap");
        pane.add(jlValidityStart, "");
        pane.add(jdtValidityStart, "wrap");
        pane.add(jlValidityPeriod, "");
        pane.add(jvpValidityPeriod, "wrap");
        pane.add(jlValidityEnd, "");
        pane.add(jdtValidityEnd, "wrap");
        pane.add(jlSerialNumber, "");
        pane.add(jtfSerialNumber, "wrap");
        pane.add(jbTransferExtensions, "spanx, split 2");
        pane.add(jbAddExtensions, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jpButtons, "right, spanx");

        populateFields();

        jbViewCsrPublicKeyDetails.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSignCsr.this);
                pubKeyDetailsPressed();
            } finally {
                CursorUtil.setCursorFree(DSignCsr.this);
            }
        });

        jbCsrExtensions.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSignCsr.this);
                extensionsPressed();
            } finally {
                CursorUtil.setCursorFree(DSignCsr.this);
            }
        });

        jbCsrPem.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSignCsr.this);
                pemEncodingPressed();
            } finally {
                CursorUtil.setCursorFree(DSignCsr.this);
            }
        });

        jbCsrAsn1.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSignCsr.this);
                asn1DumpPressed();
            } finally {
                CursorUtil.setCursorFree(DSignCsr.this);
            }
        });

        jvpValidityPeriod.addApplyActionListener(e -> {
            Date startDate = jdtValidityStart.getDateTime();
            if (startDate == null) {
                startDate = new Date();
                jdtValidityStart.setDateTime(startDate);
            }
            jdtValidityEnd.setDateTime(jvpValidityPeriod.getValidityEnd(startDate));

        });

        jrbVersion3.addChangeListener(evt -> jbAddExtensions.setEnabled(jrbVersion3.isSelected()));

        jbTransferExtensions.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSignCsr.this);
                transferExtensionsPressed();
            } finally {
                CursorUtil.setCursorFree(DSignCsr.this);
            }
        });

        jbAddExtensions.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSignCsr.this);
                addExtensionsPressed();
            } finally {
                CursorUtil.setCursorFree(DSignCsr.this);
            }
        });

        jbOK.addActionListener(evt -> okPressed());

        jbCancel.addActionListener(evt -> cancelPressed());
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

    private void populateFields() throws CryptoException {
        if (pkcs10Csr != null) {
            populatePkcs10CsrDetails();
        } else {
            populateSpkacCsrDetails();
        }

        jdnSubjectDN.setDistinguishedName(pkcs10Csr.getSubject());
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
        byte[] sigAlgParams = extractSigAlgParams();
        SignatureType sigAlg = SignatureType.resolveOid(sigAlgId, sigAlgParams);

        if (sigAlg != null) {
            jtfCsrSignatureAlgorithm.setText(sigAlg.friendly());
        } else {
            jtfCsrSignatureAlgorithm.setText(sigAlgId);
        }

        jtfCsrSignatureAlgorithm.setCaretPosition(0);

        DialogHelper.populatePkcs10Challenge(pkcs10Csr.getAttributes(), jtfCsrChallenge);

        Attribute[] extReqAttr = pkcs10Csr.getAttributes(pkcs_9_at_extensionRequest);
        if (extReqAttr != null && extReqAttr.length > 0) {
            jbCsrExtensions.setEnabled(true);
            jbTransferExtensions.setEnabled(true);
        } else {
            jbCsrExtensions.setEnabled(false);
            jbTransferExtensions.setEnabled(false);
        }

    }

    private byte[] extractSigAlgParams() {
        ASN1Encodable sigAlgParamsAsn1 = pkcs10Csr.getSignatureAlgorithm().getParameters();
        try {
            return sigAlgParamsAsn1 == null ? null : sigAlgParamsAsn1.toASN1Primitive().getEncoded();
        } catch (IOException e) {
            return null;
        }
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
            jtfCsrPublicKey.setText(
                    MessageFormat.format(res.getString("DSignCsr.jtfCsrPublicKey.text"), jtfCsrPublicKey.getText(),
                                         "" + keySize));
        } else {
            jtfCsrPublicKey.setText(
                    MessageFormat.format(res.getString("DSignCsr.jtfCsrPublicKey.text"), jtfCsrPublicKey.getText(),
                                         "?"));
        }

        jtfCsrPublicKey.setCaretPosition(0);
    }

    private void extensionsPressed() {
        X509ExtensionSet x509ExtensionSet = Pkcs10Util.getExtensions(pkcs10Csr);

        DViewExtensions dViewExtensions = new DViewExtensions(this, res.getString("DSignCsr.Extensions.Title"),
                                                              x509ExtensionSet);
        dViewExtensions.setLocationRelativeTo(this);
        dViewExtensions.setVisible(true);
    }

    private void pemEncodingPressed() {
        try {
            DViewPem dViewCsrPem = new DViewPem(this, res.getString("DSignCsr.Pem.Title"), pkcs10Csr);
            dViewCsrPem.setLocationRelativeTo(this);
            dViewCsrPem.setVisible(true);
        } catch (CryptoException e) {
            DError.displayError(this, e);
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
        } catch (Asn1Exception | IOException e) {
            DError.displayError(this, e);
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
     * Get chosen validity start date.
     *
     * @return Validity start date or null if dialog cancelled
     */
    public Date getValidityStart() {
        return validityStart;
    }

    /**
     * Get chosen validity end date.
     *
     * @return Validity end date or null if dialog cancelled
     */
    public Date getValidityEnd() {
        return validityEnd;
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
     * Get chosen subject DN for the certificate.
     *
     * @return DN or null if dialog cancelled
     */
    public X500Name getSubjectDN() {
        return subjectDN;
    }

    /**
     * Get public key from CSR
     *
     * @return Public key
     */
    public PublicKey getPublicKey() {
        return csrPublicKey;
    }

    /**
     * Get chosen certficate extensions.
     *
     * @return Certificate extensions or null if dialog cancelled.
     */
    public X509ExtensionSet getExtensions() {
        return extensions;
    }

    protected void transferExtensionsPressed() {
        extensions = Pkcs10Util.getExtensions(pkcs10Csr);

        // the value of some extensions (e.g. AKI) might be out-dated
        try {
            X509ExtensionSetUpdater.update(extensions, csrPublicKey, issuerCertificate.getPublicKey(),
                                           X500NameUtils.x500PrincipalToX500Name(
                                                   issuerCertificate.getSubjectX500Principal()),
                                           issuerCertificate.getSerialNumber());
        } catch (CryptoException | IOException e) {
            DError.displayError(this, e);
        }
    }

    private void addExtensionsPressed() {
        DAddExtensions dAddExtensions = new DAddExtensions(this, extensions, issuerCertificate.getPublicKey(),
                                                           X500NameUtils.x500PrincipalToX500Name(
                                                                   issuerCertificate.getSubjectX500Principal()),
                                                           issuerCertificate.getSerialNumber(), csrPublicKey,
                                                           jdnSubjectDN.getDistinguishedName());
        dAddExtensions.setLocationRelativeTo(this);
        dAddExtensions.setVisible(true);

        if (dAddExtensions.getExtensions() != null) {
            // Dialog not cancelled
            extensions = dAddExtensions.getExtensions();
        }
    }

    private void pubKeyDetailsPressed() {
        try {
            DViewPublicKey dViewPublicKey = new DViewPublicKey(this, res.getString("DSignCsr.PubKeyDetails.Title"),
                                                               csrPublicKey);
            dViewPublicKey.setLocationRelativeTo(this);
            dViewPublicKey.setVisible(true);
        } catch (CryptoException e) {
            DError.displayError(this, e);
        }
    }

    private void okPressed() {

        // RFC 5280:
        //    If the subject field contains an empty sequence, then the issuing CA MUST include a
        //    subjectAltName extension that is marked as critical.
        if (jdnSubjectDN.getDistinguishedName().toString().isEmpty() && !hasCriticalSAN()) {
            JOptionPane.showMessageDialog(this, res.getString("DSignCsr.CritSANReq.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        String serialNumberStr = jtfSerialNumber.getText().trim();
        if (serialNumberStr.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DSignCsr.ValReqSerialNumber.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }
        try {
            serialNumber = SerialNumbers.parse(serialNumberStr);
            if (serialNumber.compareTo(BigInteger.ONE) < 0) {
                JOptionPane.showMessageDialog(this, res.getString("DSignCsr.SerialNumberNonZero.message"), getTitle(),
                                              JOptionPane.WARNING_MESSAGE);
                return;
            }
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, res.getString("DSignCsr.SerialNumberNotInteger.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (jrbVersion1.isSelected()) {
            version = VERSION1;
            extensions = null;
        } else {
            version = VERSION3;
        }

        signatureType = (SignatureType) jcbSignatureAlgorithm.getSelectedItem();
        validityStart = jdtValidityStart.getDateTime();
        validityEnd = jdtValidityEnd.getDateTime();

        subjectDN = jdnSubjectDN.getDistinguishedName();

        closeDialog();
    }

    private boolean hasCriticalSAN() {
        return extensions.isCritical(X509ExtensionType.SUBJECT_ALTERNATIVE_NAME.oid());
    }

    private void cancelPressed() {
        extensions = null;
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", KSE.BC);
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.genKeyPair();
        JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("cn=test"), keyPair.getPublic());
        PKCS10CertificationRequest csr = csrBuilder.build(
                new JcaContentSignerBuilder("SHA256withRSA").setProvider(KSE.BC).build(keyPair.getPrivate()));

        DSignCsr dialog = new DSignCsr(new javax.swing.JFrame(), csr, keyPair.getPrivate(), KeyPairType.RSA, null);
        DialogViewer.run(dialog);
    }
}
