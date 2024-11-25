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
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.encoders.Hex;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.keypair.KeyPairUtil;
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
    // TODO JW - Convert extensions into dialog for displaying the signed/unsigned attributes
    private JButton jbCertificates;
    private JButton jbCounterSigners;
    private JButton jbExtensions;
    private JButton jbPem;
    private JButton jbAsn1;
    private JButton jbOK;

    private CMSSignedData signedData;
    private Collection<SignerInformation> signerInfos;

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
        this.signerInfos = signers;
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

        jbCounterSigners = new JButton(res.getString("DViewSignature.jbCounterSigners.text"));
        jbCounterSigners.setToolTipText(res.getString("DViewSignature.jbCounterSigners.tooltip"));
        // TODO JW - Need mnemonic for counter signers button
        PlatformUtil.setMnemonic(jbCounterSigners, res.getString("DViewSignature.jbCounterSigners.mnemonic").charAt(0));

//        jbExtensions = new JButton(res.getString("DViewSignature.jbExtensions.text"));
//        jbExtensions.setToolTipText(res.getString("DViewSignature.jbExtensions.tooltip"));
//        PlatformUtil.setMnemonic(jbExtensions, res.getString("DViewSignature.jbExtensions.mnemonic").charAt(0));

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
        pane.add(jlContentType, "");
        pane.add(jtfContentType, "wrap");
        pane.add(jlContentDigest, "");
        pane.add(jtfContentDigest, "wrap");
        pane.add(jbCertificates, "spanx, split");
        pane.add(jbCounterSigners, "");
//      pane.add(jbExtensions, "");
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
                Date signingTime = null;
                X509Certificate cert = null;

                @SuppressWarnings("unchecked") // SignerId does not specify a type when extending Selector<T>
                Collection<X509CertificateHolder> matchedCerts = signedData.getCertificates()
                        .getMatches(signerInfo.getSID());
                // TODO JW - What to do when there isn't a matched certificate?
                // A matched certificate is needed for content digest
                if (!matchedCerts.isEmpty()) {
                    X509CertificateHolder certHolder = matchedCerts.iterator().next();
                    try {
                        // TODO JW - this verifies using the attached certs. Need to link certs to keystore to validate the chain.
                        signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
                    } catch (OperatorCreationException | CMSException | CertificateException e) {
                        // TODO JW Auto-generated catch block
                        e.printStackTrace();
                    }
                    cert = X509CertUtil.convertCertificate(certHolder);
                }
                // TODO JW - Need to check for null certificate

                // TODO JW - Make the signing time extraction logic a utility method.
                AttributeTable signedAttributes = signerInfo.getSignedAttributes();
                if (signedAttributes != null) {
                    Attribute signingTimeAttribute = signedAttributes.get(CMSAttributes.signingTime);
                    if (signingTimeAttribute != null) {
                        Enumeration<?> e = signingTimeAttribute.getAttrValues().getObjects();
                        if (e.hasMoreElements()) {
                            Object o = e.nextElement();
                            try {
                                if (o instanceof ASN1UTCTime) {
                                    signingTime = ((ASN1UTCTime) o).getAdjustedDate();
                                } else if (o instanceof ASN1GeneralizedTime) {
                                    signingTime = ((ASN1GeneralizedTime) o).getDate();
                                }
                            } catch (ParseException e1) {
                                // TODO JW Auto-generated catch block
                                e1.printStackTrace();
                            }
                        }
                    }
                }

                jtfVersion.setText(Integer.toString(signerInfo.getVersion()));
                jtfVersion.setCaretPosition(0);

                jdnSubject.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert.getSubjectX500Principal()));

                jdnIssuer.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert.getIssuerX500Principal()));

                // TODO JW - What to do if the signature doesn't have a signing time?
                if (signingTime != null) {
                    jtfSigningTime.setText(StringUtils.formatDate(signingTime));
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

                jtfContentDigest.setText(HexUtil.getHexStringWithSep(signerInfo.getContentDigest(), ':'));
                jtfContentDigest.setCaretPosition(0);

                DigestType digestType = DigestType.resolveOid(signerInfo.getDigestAlgOID());
                KeyInfo keyInfo = KeyPairUtil.getKeyInfo(cert.getPublicKey());
                String algorithm = keyInfo.getAlgorithm();
                // TODO JW - Is there a better method for getting signature algorithm name from cert algorithm?
                if (algorithm.equals("EC")) {
                    algorithm = "ECDSA";
                }
                String signatureAlgorithm = digestType.friendly().replace("-", "") + "with" + algorithm;
                SignatureType signatureType = SignatureType.resolveJce(signatureAlgorithm);
                if (signatureType != null ) {
                    jtfSignatureAlgorithm.setText(signatureType.friendly());
                    jtfSignatureAlgorithm.setCaretPosition(0);
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
                    signedData.getCertificates().getMatches(new SelectAll<X509CertificateHolder>()));
//            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
//            for (X509CertificateHolder certHolder : signedData.getCertificates()
//                    .getMatches(new SelectAll<X509CertificateHolder>())) {
//                certs.add(converter.getCertificate(certHolder));
//            }
            DViewCertificate dViewCertificates = new DViewCertificate(this,
                    res.getString("DViewSignature.Certificates.Title"), certs.toArray(X509Certificate[]::new), kseFrame,
                    DViewCertificate.NONE);
            dViewCertificates.setLocationRelativeTo(this);
            dViewCertificates.setVisible(true);
        } catch (CryptoException e) {
            DError.displayError(this, e);
        }
    }

    private void counterSignersPressed() {
        SignerInformation signer = getSelectedSignerInfo();

        try {
            DViewSignature dViewSignature = new DViewSignature(this,
                    res.getString("DViewSignature.CounterSigners.Title"), signedData,
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
            // same and the DNs are the same then it is probably the same certificate anyway
            return cert1.getSerialNumber().subtract(cert2.getSerialNumber()).intValue();
        }
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
