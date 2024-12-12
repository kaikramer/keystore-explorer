/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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

import java.awt.Color;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.text.MessageFormat;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeSet;

import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.ListModel;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.StoreException;
import org.bouncycastle.util.encoders.Hex;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.CmsUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.crypto.x509.X509CertificateGenerator;
import org.kse.crypto.x509.X509CertificateVersion;
import org.kse.gui.CursorUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.KseFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.actions.ExportTrustedCertificateAction;
import org.kse.gui.actions.ImportTrustedCertificateAction;
import org.kse.gui.actions.VerifyCertificateAction;
import org.kse.gui.crypto.JCertificateFingerprint;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.dialogs.extensions.DViewExtensions;
import org.kse.gui.error.DError;
import org.kse.gui.preferences.PreferencesManager;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.StringUtils;
import org.kse.utilities.asn1.Asn1Exception;
import org.kse.utilities.io.HexUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a PKCS #7 signature. The details of one
 * signer are displayed at a time with selector buttons allowing the
 * movement to another of the signers.
 */
public class DViewSignature extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private KsePreferences preferences = PreferencesManager.getPreferences();

    private KseFrame kseFrame;

    private JLabel jlSigners;
    private JList<SignerInformation> jlbSigners;
    private JScrollPane jspSigners;
    private JLabel jlVersion;
    private JTextField jtfVersion;
    private JLabel jlSubject;
    private JDistinguishedName jdnSubject;
    private JLabel jlIssuer;
    private JDistinguishedName jdnIssuer;
    private JLabel jlSigningTime;
    private JTextField jtfSigningTime;
    private JLabel jlSignatureAlgorithm;
    private JTextField jtfSignatureAlgorithm;
    private JLabel jlContentType;
    private JTextField jtfContentType;
    private JLabel jlContentDigest;
    private JTextField jtfContentDigest;
    private JButton jbCertificates;
    private JButton jbTimeStamp;
    private JButton jbCounterSigners;
    // TODO JW - Convert extensions into dialog for displaying the signed/unsigned attributes
    private JButton jbExtensions;
    private JButton jbPem;
    private JButton jbAsn1;
    private JButton jbOK;

    private CMSSignedData signedData;
    private CMSSignedData timeStampSigner;

    /**
     * Creates a new DViewCertificate dialog.
     *
     * @param parent       Parent frame
     * @param title        The dialog title
     * @param signedData   Signature to display
     * @param signers      Signature(s) to display
     * @param kseFrame     Reference to main class with currently opened keystores and their contents
     * @throws CryptoException A problem was encountered getting the certificates' details
     */
    public DViewSignature(Window parent, String title, CMSSignedData signedData, Collection<SignerInformation> signers,
            KseFrame kseFrame) throws CryptoException {
        super(parent, title, Dialog.ModalityType.MODELESS);
        this.kseFrame = kseFrame;
        this.signedData = signedData;
        initComponents(signers);
    }

    private void initComponents(Collection<SignerInformation> signers) throws CryptoException {
        jlSigners = new JLabel(res.getString("DViewSignature.jlSigners.text"));

        jlbSigners = new JList<>(createSignerList(signers));
        // TODO JW - Signer list row height?
//        jlbSigners.setRowHeight(Math.max(18, jlbSigners.getRowHeight()));
        jlbSigners.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ToolTipManager.sharedInstance().registerComponent(jlbSigners);
        jlbSigners.setCellRenderer(new SignerListCellRend(signedData));

        jspSigners = PlatformUtil.createScrollPane(jlbSigners, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                     ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspSigners.setPreferredSize(new Dimension(100, 75));

        jlVersion = new JLabel(res.getString("DViewSignature.jlVersion.text"));

        jtfVersion = new JTextField(40);
        jtfVersion.setEditable(false);
        jtfVersion.setToolTipText(res.getString("DViewSignature.jtfVersion.tooltip"));

        jlSubject = new JLabel(res.getString("DViewSignature.jlSubject.text"));

        jdnSubject = new JDistinguishedName(res.getString("DViewSignature.Subject.Title"), 40, false);
        jdnSubject.setToolTipText(res.getString("DViewSignature.jdnSubject.tooltip"));

        jlIssuer = new JLabel(res.getString("DViewSignature.jlIssuer.text"));

        jdnIssuer = new JDistinguishedName(res.getString("DViewSignature.Issuer.Title"), 40, false);
        jdnIssuer.setToolTipText(res.getString("DViewSignature.jdnIssuer.tooltip"));

        jlSigningTime = new JLabel(res.getString("DViewSignature.jlSigningTime.text"));

        jtfSigningTime = new JTextField(40);
        jtfSigningTime.setEditable(false);
        jtfSigningTime.setToolTipText(res.getString("DViewSignature.jtfSigningTime.tooltip"));

        jlSignatureAlgorithm = new JLabel(res.getString("DViewSignature.jlSignatureAlgorithm.text"));

        jtfSignatureAlgorithm = new JTextField(40);
        jtfSignatureAlgorithm.setEditable(false);
        jtfSignatureAlgorithm.setToolTipText(res.getString("DViewSignature.jtfSignatureAlgorithm.tooltip"));
        
        jlContentType = new JLabel(res.getString("DViewSignature.jlContentType.text"));

        jtfContentType = new JTextField(40);
        jtfContentType.setEditable(false);
        jtfContentType.setToolTipText(res.getString("DViewSignature.jtfContentType.tooltip"));

        jlContentDigest = new JLabel(res.getString("DViewSignature.jlContentDigest.text"));
        
        jtfContentDigest = new JTextField(40);
        jtfContentDigest.setEditable(false);
        jtfContentDigest.setToolTipText(res.getString("DViewSignature.jtfContentDigest.tooltip"));

        jbCertificates = new JButton(res.getString("DViewSignature.jbCertificates.text"));
        jbCertificates.setToolTipText(res.getString("DViewSignature.jbCertificates.tooltip"));
        PlatformUtil.setMnemonic(jbCertificates, res.getString("DViewSignature.jbCertificates.mnemonic").charAt(0));

        jbTimeStamp = new JButton(res.getString("DViewSignature.jbTimeStamp.text"));
        jbTimeStamp.setToolTipText(res.getString("DViewSignature.jbTimeStamp.tooltip"));
        // TODO JW - Need mnemonic for time stamp button
//        PlatformUtil.setMnemonic(jbTimeStamp, res.getString("DViewSignature.jbTimeStamp.mnemonic").charAt(0));

        jbCounterSigners = new JButton(res.getString("DViewSignature.jbCounterSigners.text"));
        jbCounterSigners.setToolTipText(res.getString("DViewSignature.jbCounterSigners.tooltip"));
        // TODO JW - Need mnemonic for counter signers button
        PlatformUtil.setMnemonic(jbCounterSigners, res.getString("DViewSignature.jbCounterSigners.mnemonic").charAt(0));

//        jbExtensions = new JButton(res.getString("DViewSignature.jbExtensions.text"));
//        jbExtensions.setToolTipText(res.getString("DViewSignature.jbExtensions.tooltip"));
//        PlatformUtil.setMnemonic(jbExtensions, res.getString("DViewSignature.jbExtensions.mnemonic").charAt(0));

        // TODO JW - Display PEM and ASN1 buttons for counter signatures? What about for time stamps?
        // TODO JW - Need to make certain these buttons work as expected.
        jbPem = new JButton(res.getString("DViewSignature.jbPem.text"));
        jbPem.setToolTipText(res.getString("DViewSignature.jbPem.tooltip"));
        PlatformUtil.setMnemonic(jbPem, res.getString("DViewSignature.jbPem.mnemonic").charAt(0));

        jbAsn1 = new JButton(res.getString("DViewSignature.jbAsn1.text"));
        jbAsn1.setToolTipText(res.getString("DViewSignature.jbAsn1.tooltip"));
        PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewSignature.jbAsn1.mnemonic").charAt(0));

        jbOK = new JButton(res.getString("DViewSignature.jbOK.text"));

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
        pane.add(jlSigners, "");
        pane.add(jspSigners, "sgx, wrap");
        pane.add(jlVersion, "");
        pane.add(jtfVersion, "sgx, wrap");
        pane.add(jlSubject, "");
        pane.add(jdnSubject, "wrap");
        pane.add(jlIssuer, "");
        pane.add(jdnIssuer, "wrap");
        pane.add(jlSigningTime, "");
        pane.add(jtfSigningTime, "wrap");
        pane.add(jlSignatureAlgorithm, "");
        pane.add(jtfSignatureAlgorithm, "wrap");
        // TODO JW - clean up the dialog
//        pane.add(jlContentType, "");
//        pane.add(jtfContentType, "wrap");
//        pane.add(jlContentDigest, "");
//        pane.add(jtfContentDigest, "wrap");
        pane.add(jbTimeStamp, "spanx, split");
        pane.add(jbCounterSigners, "wrap");
//      pane.add(jbExtensions, "");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jbCertificates, "spanx, split");
        // TODO JW - Hide PEM and ASN.1 buttons for Counter Signers.
        // Bouncy Castle CMS does not expose the ASN1 encoding for SignerInfos or other aspects of the CMS data.
        pane.add(jbPem, "");
        pane.add(jbAsn1, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jbOK, "spanx, tag ok");

        jlbSigners.addListSelectionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewSignature.this);
                populateDetails();
            } finally {
                CursorUtil.setCursorFree(DViewSignature.this);
            }
        });

        jbOK.addActionListener(evt -> okPressed());

        jbCertificates.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewSignature.this);
                certificatesPressed();
            } finally {
                CursorUtil.setCursorFree(DViewSignature.this);
            }
        });

        jbTimeStamp.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewSignature.this);
                timeStampPressed();
            } finally {
                CursorUtil.setCursorFree(DViewSignature.this);
            }
        });

        jbCounterSigners.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewSignature.this);
                counterSignersPressed();
            } finally {
                CursorUtil.setCursorFree(DViewSignature.this);
            }
        });

//        jbExtensions.addActionListener(evt -> {
//            try {
//                CursorUtil.setCursorBusy(DViewSignature.this);
//                extensionsPressed();
//            } finally {
//                CursorUtil.setCursorFree(DViewSignature.this);
//            }
//        });

        jbPem.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewSignature.this);
                pemEncodingPressed();
            } finally {
                CursorUtil.setCursorFree(DViewSignature.this);
            }
        });

        jbAsn1.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewSignature.this);
                asn1DumpPressed();
            } finally {
                CursorUtil.setCursorFree(DViewSignature.this);
            }
        });

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setResizable(false);

        // select first signer in signer list
        jlbSigners.setSelectedIndex(0);

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

    private ListModel<SignerInformation> createSignerList(Collection<SignerInformation> signers) {
        DefaultListModel<SignerInformation> signerList = new DefaultListModel<>();
        
        signerList.addAll(signers);

        return signerList;
    }

    private SignerInformation getSelectedSignerInfo() {
        return jlbSigners.getSelectedValue();
    }

    private void populateDetails() {
        SignerInformation signerInfo = getSelectedSignerInfo();

        if (signerInfo == null) {
            jdnSubject.setEnabled(false);
            jdnIssuer.setEnabled(false);
            jbCertificates.setEnabled(false);
            jbTimeStamp.setEnabled(false);
            jbCounterSigners.setEnabled(false);
//            jbExtensions.setEnabled(false);
            jbPem.setEnabled(false);
            jbAsn1.setEnabled(false);

            jtfVersion.setText("");
            jdnSubject.setDistinguishedName(null);
            jdnIssuer.setDistinguishedName(null);
            jtfSigningTime.setText("");
            jtfSignatureAlgorithm.setText("");
            jtfContentType.setText("");
            jtfContentDigest.setText("");
        } else {
            jdnSubject.setEnabled(true);
            jdnIssuer.setEnabled(true);
//            jbExtensions.setEnabled(true);
            jbPem.setEnabled(true);
            jbAsn1.setEnabled(true);

            try {
                Date signingTime = CmsUtil.getSigningTime(signerInfo);
                X509Certificate cert = X509CertUtil.convertCertificate(CmsUtil.getSignerCert(signedData, signerInfo));

                // TODO JW - Need to check for null certificate (see CmsUtil.getSignerCert)

                jtfVersion.setText(Integer.toString(signerInfo.getVersion()));
                jtfVersion.setCaretPosition(0);

                jdnSubject.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert.getSubjectX500Principal()));

                jdnIssuer.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert.getIssuerX500Principal()));

                if (signingTime != null) {
                    jtfSigningTime.setText(StringUtils.formatDate(signingTime));
                } else {
                    // TODO JW - What to do if the signature doesn't have a signing time?
                    jtfSigningTime.setText("");
                }

//                if (noLongerValid) {
//                    jtfSigningTime.setText(
//                            MessageFormat.format(res.getString("DViewCertificate.jtfSigningTime.expired.text"),
//                                                 jtfSigningTime.getText()));
//                    jtfSigningTime.setForeground(Color.red);
//                } else {
//                    jtfSigningTime.setForeground(jtfVersion.getForeground());
//                }
                jtfSigningTime.setCaretPosition(0);

                // TODO JW - These map strings need to be moved to a resource bundle.
                Map<ASN1ObjectIdentifier, String> CONTENT_TYPES = new HashMap<>();
                CONTENT_TYPES.put(PKCSObjectIdentifiers.data, "Data");
                CONTENT_TYPES.put(PKCSObjectIdentifiers.signedData, "Signed Data");
                CONTENT_TYPES.put(PKCSObjectIdentifiers.envelopedData, "Enveloped Data");
                CONTENT_TYPES.put(PKCSObjectIdentifiers.signedAndEnvelopedData, "Signed and Enveloped Data");
                CONTENT_TYPES.put(PKCSObjectIdentifiers.digestedData, "Digested Data");
                CONTENT_TYPES.put(PKCSObjectIdentifiers.encryptedData, "Encrypted Data");
                jtfContentType.setText(CONTENT_TYPES.get(signerInfo.getContentType()));
                jtfContentType.setCaretPosition(0);

                // TODO JW - digest is only available after verify is called.
//                jtfContentDigest.setText(HexUtil.getHexStringWithSep(signerInfo.getContentDigest(), ':'));
//                jtfContentDigest.setCaretPosition(0);

                SignatureType signatureType = lookupSignatureType(signerInfo);
                if (signatureType != null ) {
                    jtfSignatureAlgorithm.setText(signatureType.friendly());
                } else {
                    jtfSignatureAlgorithm.setText("");
                }
                jtfSignatureAlgorithm.setCaretPosition(0);

                timeStampSigner = CmsUtil.getTimeStampSignature(signerInfo);

                if (timeStampSigner != null) {
                    jbTimeStamp.setEnabled(true);
                } else {
                    jbTimeStamp.setEnabled(false);
                }

                if (signerInfo.getCounterSignatures().size() > 0) {
                    jbCounterSigners.setEnabled(true);
                } else {
                    jbCounterSigners.setEnabled(false);
                }

//                Set<?> critExts = signerInfo.getCriticalExtensionOIDs();
//                Set<?> nonCritExts = signerInfo.getNonCriticalExtensionOIDs();
//
//                if ((critExts != null && !critExts.isEmpty()) || (nonCritExts != null && !nonCritExts.isEmpty())) {
//                    jbExtensions.setEnabled(true);
//                } else {
//                    jbExtensions.setEnabled(false);
//                }
            } catch (CryptoException e) {
                DError.displayError(this, e);
                dispose();
            }
        }
    }

    private SignatureType lookupSignatureType(SignerInformation signerInfo) {
        SignatureType signatureType = null;

        if (PKCSObjectIdentifiers.rsaEncryption.getId().equals(signerInfo.getEncryptionAlgOID())) {
            // Lookup by JCE name for RSA
            DigestType digestType = DigestType.resolveOid(signerInfo.getDigestAlgOID());
            String signatureAlgorithm = digestType.friendly().replace("-", "") + "withRSA";
            signatureType = SignatureType.resolveJce(signatureAlgorithm);
        } else {
            signatureType = SignatureType.resolveOid(signerInfo.getEncryptionAlgOID(),
                    signerInfo.getEncryptionAlgParams());
        }
        return signatureType;
    }

    private static class SelectAll<T> implements Selector<T> {
        @Override
        public Object clone() {
            return null;
        }

        @Override
        public boolean match(T obj) {
            return true;
        }
    }

    private void certificatesPressed() {
        try {
            List<X509Certificate> certs = X509CertUtil.convertCertificateHolders(
                    signedData.getCertificates().getMatches(new SelectAll<>()));
            DViewCertificate dViewCertificates = new DViewCertificate(this,
                    res.getString("DViewSignature.Certificates.Title"), certs.toArray(X509Certificate[]::new), kseFrame,
                    DViewCertificate.NONE);
            dViewCertificates.setLocationRelativeTo(this);
            dViewCertificates.setVisible(true);
        } catch (CryptoException e) {
            DError.displayError(this, e);
        }
    }

    private void timeStampPressed() {
        SignerInformation signer = getSelectedSignerInfo();

        try {
            String shortName = CmsUtil.getShortName(CmsUtil.getSignerCert(signedData, signer));

            DViewSignature dViewSignature = new DViewSignature(this,
                    MessageFormat.format(res.getString("DViewSignature.TimeStampSigner.Title"), shortName),
                    timeStampSigner, timeStampSigner.getSignerInfos().getSigners(), null);
            dViewSignature.setLocationRelativeTo(this);
            dViewSignature.setVisible(true);
        } catch (CryptoException e) {
            DError.displayError(this, e);
        }
    }

    private void counterSignersPressed() {
        SignerInformation signer = getSelectedSignerInfo();

        try {
            String shortName = CmsUtil.getShortName(CmsUtil.getSignerCert(signedData, signer));

            DViewSignature dViewSignature = new DViewSignature(this,
                    MessageFormat.format(res.getString("DViewSignature.CounterSigners.Title"), shortName), signedData,
                    signer.getCounterSignatures().getSigners(), null);
            dViewSignature.setLocationRelativeTo(this);
            dViewSignature.setVisible(true);
        } catch (CryptoException e) {
            DError.displayError(this, e);
        }
    }

//    private void extensionsPressed() {
//        X509Certificate cert = getSelectedSignerInfo();
//
//        DViewExtensions dViewExtensions = new DViewExtensions(this, res.getString("DViewCertificate.Extensions.Title"),
//                cert, kseFrame);
//        dViewExtensions.setLocationRelativeTo(this);
//        dViewExtensions.setVisible(true);
//    }

    private void pemEncodingPressed() {
        try {
            DViewPem dViewCertPem = new DViewPem(this, res.getString("DViewSignature.Pem.Title"), signedData);
            dViewCertPem.setLocationRelativeTo(this);
            dViewCertPem.setVisible(true);
        } catch (CryptoException e) {
            DError.displayError(this, e);
        }
    }

    private void asn1DumpPressed() {
        // TODO JW - Should this show only the ASN.1 for the selected signer?
        try {
            DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, signedData);
            dViewAsn1Dump.setLocationRelativeTo(this);
            dViewAsn1Dump.setVisible(true);
        } catch (Asn1Exception | IOException e) {
            DError.displayError(this, e);
        }
    }

    private void okPressed() {
        // TODO JW - set any preferences here (e.g., chosen fingerprint algorithm)
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", KSE.BC);

        KeyPair caKeyPair = keyGen.genKeyPair();
        X509CertificateGenerator certGen = new X509CertificateGenerator(X509CertificateVersion.VERSION3);
        X509Certificate caCert = certGen.generateSelfSigned(new X500Name("cn=CA"), Date.from(Instant.now()),
                                                            Date.from(Instant.now().plus(3650, ChronoUnit.DAYS)),
                                                            caKeyPair.getPublic(), caKeyPair.getPrivate(),
                                                            SignatureType.SHA224WITHRSAANDMGF1, new BigInteger(
                        Hex.decode("1122334455667788990011223344556677889900")));

        KeyPair eeKeyPair = keyGen.genKeyPair();
        X509Certificate eeCert = certGen.generate(new X500Name("cn=EE"), X500NameUtils.x500PrincipalToX500Name(
                                                          caCert.getSubjectX500Principal()), Date.from(Instant.now()),
                                                  Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                                                  eeKeyPair.getPublic(), eeKeyPair.getPrivate(),
                                                  SignatureType.SHA224WITHRSAANDMGF1, new BigInteger(
                        Hex.decode("0011223344556677889900112233445566778899")));

        X509Certificate[] certs = new X509Certificate[] { eeCert, caCert };

        // TODO JW - fix main method
//        DViewSignature dialog = new DViewSignature(new javax.swing.JFrame(), "Title", certs, new KseFrame(),
//                                                       IMPORT_EXPORT);
//        DialogViewer.run(dialog);
    }
}
