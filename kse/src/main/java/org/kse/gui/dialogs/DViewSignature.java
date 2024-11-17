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
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.encoders.Hex;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
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

    public static final int NONE = 0;
    public static final int IMPORT = 1;
    public static final int EXPORT = 2;
    public static final int IMPORT_EXPORT = 3;
    private int importExport = 0;

    private KseFrame kseFrame;

    private JLabel jlSigners;
    private JList<SignerInformation> jlbSigners;
    private JScrollPane jspSigners;
    private JLabel jlSignerDN;
    private JTextField jtfSignerDN;
    private JLabel jlSerial;
    private JDistinguishedName jdnSerial;
    private JLabel jlIssuer;
    private JDistinguishedName jdnIssuer;
    private JLabel jlSerialNumberHex;
    private JTextField jtfSerialNumberHex;
    private JLabel jlSerialNumberDec;
    private JTextField jtfSerialNumberDec;
    private JLabel jlValidFrom;
    private JTextField jtfValidFrom;
    private JLabel jlValidUntil;
    private JTextField jtfValidUntil;
    private JLabel jlPublicKey;
    private JTextField jtfPublicKey;
    private JButton jbViewPublicKeyDetails;
    private JLabel jlSignatureAlgorithm;
    private JTextField jtfSignatureAlgorithm;
    private JLabel jlFingerprint;
    private JCertificateFingerprint jcfFingerprint;
    private JButton jbExtensions;
    private JButton jbPem;
    private JButton jbAsn1;
    private JButton jbImport;
    private JButton jbExport;
    private JButton jbOK;
    private JButton jbVerify;

    private CMSSignedData signedData;

    /**
     * Creates a new DViewCertificate dialog.
     *
     * @param parent       Parent frame
     * @param title        The dialog title
     * @param signedData   Signature to display
     * @param kseFrame     Reference to main class with currently opened keystores and their contents
     * @param importExport Show import button/export button/no extra button?
     * @throws CryptoException A problem was encountered getting the certificates' details
     */
    public DViewSignature(Window parent, String title, CMSSignedData signedData, KseFrame kseFrame, int importExport)
            throws CryptoException {
        super(parent, title, Dialog.ModalityType.MODELESS);
        this.kseFrame = kseFrame;
        this.importExport = importExport;
        this.signedData = signedData;
        initComponents(signedData);
    }

    private void initComponents(CMSSignedData signedData) throws CryptoException {
        jlSigners = new JLabel(res.getString("DViewCertificate.jlHierarchy.text"));

        jlbSigners = new JList<>(createSignerList(signedData));
        // TODO JW - Signer list row height?
//        jlbSigners.setRowHeight(Math.max(18, jlbSigners.getRowHeight()));
        jlbSigners.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ToolTipManager.sharedInstance().registerComponent(jlbSigners);
        jlbSigners.setCellRenderer(new SignerListCellRend());

        jspSigners = PlatformUtil.createScrollPane(jlbSigners, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                     ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspSigners.setPreferredSize(new Dimension(100, 75));

        jlSignerDN = new JLabel(res.getString("DViewCertificate.jlVersion.text"));

        jtfSignerDN = new JTextField(40);
        jtfSignerDN.setEditable(false);
        jtfSignerDN.setToolTipText(res.getString("DViewCertificate.jtfVersion.tooltip"));

        jlSerial = new JLabel(res.getString("DViewCertificate.jlSubject.text"));

        jdnSerial = new JDistinguishedName(res.getString("DViewCertificate.Subject.Title"), 40, false);
        jdnSerial.setToolTipText(res.getString("DViewCertificate.jdnSubject.tooltip"));

        jlIssuer = new JLabel(res.getString("DViewCertificate.jlIssuer.text"));

        jdnIssuer = new JDistinguishedName(res.getString("DViewCertificate.Issuer.Title"), 40, false);
        jdnIssuer.setToolTipText(res.getString("DViewCertificate.jdnIssuer.tooltip"));

        jlSerialNumberHex = new JLabel(res.getString("DViewCertificate.jlSerialNumberHex.text"));

        jtfSerialNumberHex = new JTextField(40);
        jtfSerialNumberHex.setEditable(false);
        jtfSerialNumberHex.setToolTipText(res.getString("DViewCertificate.jtfSerialNumberHex.tooltip"));
        jtfSerialNumberHex.setCaretPosition(0);

        jlSerialNumberDec = new JLabel(res.getString("DViewCertificate.jlSerialNumberDec.text"));

        jtfSerialNumberDec = new JTextField(40);
        jtfSerialNumberDec.setEditable(false);
        jtfSerialNumberDec.setToolTipText(res.getString("DViewCertificate.jtfSerialNumberDec.tooltip"));
        jtfSerialNumberDec.setCaretPosition(0);

        jlValidFrom = new JLabel(res.getString("DViewCertificate.jlValidFrom.text"));

        jtfValidFrom = new JTextField(40);
        jtfValidFrom.setEditable(false);
        jtfValidFrom.setToolTipText(res.getString("DViewCertificate.jtfValidFrom.tooltip"));

        jlValidUntil = new JLabel(res.getString("DViewCertificate.jlValidUntil.text"));

        jtfValidUntil = new JTextField(40);
        jtfValidUntil.setEditable(false);
        jtfValidUntil.setToolTipText(res.getString("DViewCertificate.jtfValidUntil.tooltip"));

        jlPublicKey = new JLabel(res.getString("DViewCertificate.jlPublicKey.text"));

        jtfPublicKey = new JTextField(40);
        jtfPublicKey.setEditable(false);
        jtfPublicKey.setToolTipText(res.getString("DViewCertificate.jtfPublicKey.tooltip"));

        jbViewPublicKeyDetails = new JButton();
        jbViewPublicKeyDetails.setToolTipText(res.getString("DViewCertificate.jbViewPublicKeyDetails.tooltip"));
        jbViewPublicKeyDetails.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/viewpubkey.png"))));

        jlSignatureAlgorithm = new JLabel(res.getString("DViewCertificate.jlSignatureAlgorithm.text"));

        jtfSignatureAlgorithm = new JTextField(40);
        jtfSignatureAlgorithm.setEditable(false);
        jtfSignatureAlgorithm.setToolTipText(res.getString("DViewCertificate.jtfSignatureAlgorithm.tooltip"));

        jlFingerprint = new JLabel(res.getString("DViewCertificate.jlFingerprint.text"));

        jcfFingerprint = new JCertificateFingerprint(30);

        jbExtensions = new JButton(res.getString("DViewCertificate.jbExtensions.text"));
        jbExtensions.setToolTipText(res.getString("DViewCertificate.jbExtensions.tooltip"));
        PlatformUtil.setMnemonic(jbExtensions, res.getString("DViewCertificate.jbExtensions.mnemonic").charAt(0));

        jbPem = new JButton(res.getString("DViewCertificate.jbPem.text"));
        jbPem.setToolTipText(res.getString("DViewCertificate.jbPem.tooltip"));
        PlatformUtil.setMnemonic(jbPem, res.getString("DViewCertificate.jbPem.mnemonic").charAt(0));

        jbAsn1 = new JButton(res.getString("DViewCertificate.jbAsn1.text"));
        jbAsn1.setToolTipText(res.getString("DViewCertificate.jbAsn1.tooltip"));
        PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewCertificate.jbAsn1.mnemonic").charAt(0));

        jbImport = new JButton(res.getString("DViewCertificate.jbImportExport.import.text"));
        jbImport.setToolTipText(res.getString("DViewCertificate.jbImportExport.import.tooltip"));
        jbImport.setVisible(importExport == IMPORT || importExport == IMPORT_EXPORT);
        PlatformUtil.setMnemonic(jbImport, res.getString("DViewCertificate.jbImport.mnemonic").charAt(0));

        jbExport = new JButton(res.getString("DViewCertificate.jbImportExport.export.text"));
        jbExport.setToolTipText(res.getString("DViewCertificate.jbImportExport.export.tooltip"));
        jbExport.setVisible(importExport == EXPORT || importExport == IMPORT_EXPORT);
        PlatformUtil.setMnemonic(jbExport, res.getString("DViewCertificate.jbExport.mnemonic").charAt(0));

        jbOK = new JButton(res.getString("DViewCertificate.jbOK.text"));

        jbVerify = new JButton(res.getString("DViewCertificate.jbVerify.text"));
        jbVerify.setToolTipText(res.getString("DViewCertificate.jbVerify.tooltip"));
        jbVerify.setVisible(importExport != NONE);
        PlatformUtil.setMnemonic(jbVerify, res.getString("DViewCertificate.jbVerify.mnemonic").charAt(0));

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
        pane.add(jlSigners, "");
        pane.add(jspSigners, "sgx, wrap");
        pane.add(jlSignerDN, "");
        pane.add(jtfSignerDN, "sgx, wrap");
        pane.add(jlSerial, "");
        pane.add(jdnSerial, "wrap");
        pane.add(jlIssuer, "");
        pane.add(jdnIssuer, "wrap");
        pane.add(jlSerialNumberHex, "");
        pane.add(jtfSerialNumberHex, "wrap");
        pane.add(jlSerialNumberDec, "");
        pane.add(jtfSerialNumberDec, "wrap");
        pane.add(jlValidFrom, "");
        pane.add(jtfValidFrom, "wrap");
        pane.add(jlValidUntil, "");
        pane.add(jtfValidUntil, "wrap");
        pane.add(jlPublicKey, "");
        pane.add(jtfPublicKey, "spanx, split");
        pane.add(jbViewPublicKeyDetails, "wrap");
        pane.add(jlSignatureAlgorithm, "");
        pane.add(jtfSignatureAlgorithm, "wrap");
        pane.add(jlFingerprint, "");
        pane.add(jcfFingerprint, "spanx, growx, wrap");
        pane.add(jbImport, "hidemode 1, spanx, split");
        pane.add(jbExport, "hidemode 1");
        pane.add(jbExtensions, "");
        pane.add(jbPem, "");
        pane.add(jbVerify, "hidemode 1");
        pane.add(jbAsn1, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jbOK, "spanx, tag ok");

        // TODO JW - list selection listener
//        jlbSigners.addTreeSelectionListener(evt -> {
//            try {
//                CursorUtil.setCursorBusy(DViewSignature.this);
//                populateDetails();
//            } finally {
//                CursorUtil.setCursorFree(DViewSignature.this);
//            }
//        });

        jbOK.addActionListener(evt -> okPressed());

//        jbExport.addActionListener(evt -> {
//            try {
//                CursorUtil.setCursorBusy(DViewSignature.this);
//                exportPressed();
//            } finally {
//                CursorUtil.setCursorFree(DViewSignature.this);
//            }
//        });
//
//        jbExtensions.addActionListener(evt -> {
//            try {
//                CursorUtil.setCursorBusy(DViewSignature.this);
//                extensionsPressed();
//            } finally {
//                CursorUtil.setCursorFree(DViewSignature.this);
//            }
//        });
//
//        jbImport.addActionListener(evt -> {
//            try {
//                CursorUtil.setCursorBusy(DViewSignature.this);
//                importPressed();
//            } finally {
//                CursorUtil.setCursorFree(DViewSignature.this);
//            }
//        });
//
//        jbViewPublicKeyDetails.addActionListener(evt -> {
//            try {
//                CursorUtil.setCursorBusy(DViewSignature.this);
//                pubKeyDetailsPressed();
//            } finally {
//                CursorUtil.setCursorFree(DViewSignature.this);
//            }
//        });
//
//        jbPem.addActionListener(evt -> {
//            try {
//                CursorUtil.setCursorBusy(DViewSignature.this);
//                pemEncodingPressed();
//            } finally {
//                CursorUtil.setCursorFree(DViewSignature.this);
//            }
//        });
//
//        jbAsn1.addActionListener(evt -> {
//            try {
//                CursorUtil.setCursorBusy(DViewSignature.this);
//                asn1DumpPressed();
//            } finally {
//                CursorUtil.setCursorFree(DViewSignature.this);
//            }
//        });
//
//        jbVerify.addActionListener(evt -> {
//            try {
//                CursorUtil.setCursorBusy(DViewSignature.this);
//                verifyPressed();
//            } finally {
//                CursorUtil.setCursorFree(DViewSignature.this);
//            }
//        });

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setResizable(false);

        // TODO JW - select first entry in list
        // select (first) leaf in certificate tree
//        DefaultMutableTreeNode firstLeaf = ((DefaultMutableTreeNode) topNode).getFirstLeaf();
//        jlbSigners.setSelectionPath(new TreePath(firstLeaf.getPath()));

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

//    private void verifyPressed() {
//
//        X509Certificate cert = getSelectedCertificate();
//        new VerifyCertificateAction(kseFrame, cert, chain).actionPerformed(null);
//    }

    private ListModel<SignerInformation> createSignerList(CMSSignedData signedData) {
        DefaultListModel<SignerInformation> signerList = new DefaultListModel<>();
        
        signerList.addAll(signedData.getSignerInfos().getSigners());

        return signerList;
    }

//    private X509Certificate getSelectedCertificate() {
//        TreePath[] selections = jlbSigners.getSelectionPaths();
//
//        if (selections == null) {
//            return null;
//        }
//
//        return (X509Certificate) ((DefaultMutableTreeNode) selections[0].getLastPathComponent()).getUserObject();
//    }

//    private void populateDetails() {
//        X509Certificate cert = getSelectedCertificate();
//
//        if (cert == null) {
//            jdnSerial.setEnabled(false);
//            jdnIssuer.setEnabled(false);
//            jbViewPublicKeyDetails.setEnabled(false);
//            jcfFingerprint.setEnabled(false);
//            jbExtensions.setEnabled(false);
//            jbPem.setEnabled(false);
//            jbAsn1.setEnabled(false);
//
//            jtfSignerDN.setText("");
//            jdnSerial.setDistinguishedName(null);
//            jdnIssuer.setDistinguishedName(null);
//            jtfSerialNumberHex.setText("");
//            jtfSerialNumberDec.setText("");
//            jtfValidFrom.setText("");
//            jtfValidUntil.setText("");
//            jtfPublicKey.setText("");
//            jtfSignatureAlgorithm.setText("");
//            jcfFingerprint.setEncodedCertificate(null);
//        } else {
//            jdnSerial.setEnabled(true);
//            jdnIssuer.setEnabled(true);
//            jbViewPublicKeyDetails.setEnabled(true);
//            jbExtensions.setEnabled(true);
//            jbPem.setEnabled(true);
//            jbAsn1.setEnabled(true);
//
//            try {
//                Date currentDate = new Date();
//
//                Date startDate = cert.getNotBefore();
//                Date endDate = cert.getNotAfter();
//
//                boolean notYetValid = currentDate.before(startDate);
//                boolean noLongerValid = currentDate.after(endDate);
//
//                jtfSignerDN.setText(Integer.toString(cert.getVersion()));
//                jtfSignerDN.setCaretPosition(0);
//
//                jdnSerial.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert.getSubjectX500Principal()));
//
//                jdnIssuer.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert.getIssuerX500Principal()));
//
//                jtfSerialNumberHex.setText(X509CertUtil.getSerialNumberAsHex(cert));
//                jtfSerialNumberHex.setCaretPosition(0);
//
//                jtfSerialNumberDec.setText(X509CertUtil.getSerialNumberAsDec(cert));
//                jtfSerialNumberDec.setCaretPosition(0);
//
//                jtfValidFrom.setText(StringUtils.formatDate(startDate));
//
//                if (notYetValid) {
//                    jtfValidFrom.setText(
//                            MessageFormat.format(res.getString("DViewCertificate.jtfValidFrom.notyetvalid.text"),
//                                                 jtfValidFrom.getText()));
//                    jtfValidFrom.setForeground(Color.red);
//                } else {
//                    jtfValidFrom.setForeground(jtfSignerDN.getForeground());
//                }
//                jtfValidFrom.setCaretPosition(0);
//
//                jtfValidUntil.setText(StringUtils.formatDate(endDate));
//
//                if (noLongerValid) {
//                    jtfValidUntil.setText(
//                            MessageFormat.format(res.getString("DViewCertificate.jtfValidUntil.expired.text"),
//                                                 jtfValidUntil.getText()));
//                    jtfValidUntil.setForeground(Color.red);
//                } else {
//                    jtfValidUntil.setForeground(jtfSignerDN.getForeground());
//                }
//                jtfValidUntil.setCaretPosition(0);
//
//                KeyInfo keyInfo = KeyPairUtil.getKeyInfo(cert.getPublicKey());
//                jtfPublicKey.setText(keyInfo.getAlgorithm());
//                Integer keySize = keyInfo.getSize();
//
//                if (keySize != null) {
//                    jtfPublicKey.setText(MessageFormat.format(res.getString("DViewCertificate.jtfPublicKey.text"),
//                                                              jtfPublicKey.getText(), "" + keySize));
//                } else {
//                    jtfPublicKey.setText(MessageFormat.format(res.getString("DViewCertificate.jtfPublicKey.text"),
//                                                              jtfPublicKey.getText(), "?"));
//                }
//                if (cert.getPublicKey() instanceof ECPublicKey) {
//                    jtfPublicKey.setText(jtfPublicKey.getText() + " (" + keyInfo.getDetailedAlgorithm() + ")");
//                }
//                jtfPublicKey.setCaretPosition(0);
//
//                jtfSignatureAlgorithm.setText(X509CertUtil.getCertificateSignatureAlgorithm(cert));
//                jtfSignatureAlgorithm.setCaretPosition(0);
//
//                byte[] encodedCertificate;
//                try {
//                    encodedCertificate = cert.getEncoded();
//                } catch (CertificateEncodingException ex) {
//                    throw new CryptoException(res.getString("DViewCertificate.NoGetEncodedCert.exception.message"), ex);
//                }
//
//                jcfFingerprint.setEncodedCertificate(encodedCertificate);
//
//                jcfFingerprint.setFingerprintAlg(preferences.getCertificateFingerprintAlgorithm());
//
//                Set<?> critExts = cert.getCriticalExtensionOIDs();
//                Set<?> nonCritExts = cert.getNonCriticalExtensionOIDs();
//
//                if ((critExts != null && !critExts.isEmpty()) || (nonCritExts != null && !nonCritExts.isEmpty())) {
//                    jbExtensions.setEnabled(true);
//                } else {
//                    jbExtensions.setEnabled(false);
//                }
//            } catch (CryptoException e) {
//                DError.displayError(this, e);
//                dispose();
//            }
//        }
//    }
//
//    private void pubKeyDetailsPressed() {
//        try {
//            X509Certificate cert = getSelectedCertificate();
//
//            DViewPublicKey dViewPublicKey = new DViewPublicKey(this,
//                                                               res.getString("DViewCertificate.PubKeyDetails.Title"),
//                                                               cert.getPublicKey());
//            dViewPublicKey.setLocationRelativeTo(this);
//            dViewPublicKey.setVisible(true);
//        } catch (CryptoException e) {
//            DError.displayError(this, e);
//        }
//    }
//
//    private void extensionsPressed() {
//        X509Certificate cert = getSelectedCertificate();
//
//        DViewExtensions dViewExtensions = new DViewExtensions(this, res.getString("DViewCertificate.Extensions.Title"),
//                cert, kseFrame);
//        dViewExtensions.setLocationRelativeTo(this);
//        dViewExtensions.setVisible(true);
//    }
//
//    private void pemEncodingPressed() {
//        X509Certificate cert = getSelectedCertificate();
//
//        try {
//            DViewPem dViewCertPem = new DViewPem(this, res.getString("DViewCertificate.Pem.Title"), cert);
//            dViewCertPem.setLocationRelativeTo(this);
//            dViewCertPem.setVisible(true);
//        } catch (CryptoException e) {
//            DError.displayError(this, e);
//        }
//    }
//
//    private void asn1DumpPressed() {
//        X509Certificate cert = getSelectedCertificate();
//
//        try {
//            DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, cert);
//            dViewAsn1Dump.setLocationRelativeTo(this);
//            dViewAsn1Dump.setVisible(true);
//        } catch (Asn1Exception | IOException e) {
//            DError.displayError(this, e);
//        }
//    }
//
//    private void importPressed() {
//        X509Certificate cert = getSelectedCertificate();
//        new ImportTrustedCertificateAction(kseFrame, cert).actionPerformed(null);
//    }
//
//    private void exportPressed() {
//        X509Certificate cert = getSelectedCertificate();
//        new ExportTrustedCertificateAction(kseFrame, cert).actionPerformed(null);
//    }

    private void okPressed() {
        preferences.setCertificateFingerprintAlgorithm(jcfFingerprint.getSelectedFingerprintAlg());
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
