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

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Window;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.signing.CmsSignatureStatus;
import org.kse.crypto.signing.CmsSigner;
import org.kse.crypto.signing.CmsUtil;
import org.kse.crypto.signing.KseSignerInformation;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.crypto.x509.X509CertificateGenerator;
import org.kse.crypto.x509.X509CertificateVersion;
import org.kse.gui.CursorUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.error.DError;
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

    private KseFrame kseFrame;

    private JLabel jlSigners;
    private JTree jtrSigners;
    private JScrollPane jspSigners;
    private JLabel jlStatus;
    private JTextField jtfStatus;
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
    private JButton jbTimeStamp;
    private JButton jbSignerAsn1;
    private JButton jbCertificates;
    private JButton jbPem;
    private JButton jbAsn1;
    private JButton jbOK;

    private CMSSignedData signedData;
    private Store<X509CertificateHolder> tsaTrustedCerts;
    private CMSSignedData timeStampSigner;

    /**
     * Creates a new DViewCertificate dialog.
     *
     * @param parent          Parent frame
     * @param title           The dialog title
     * @param signedData      Signature to display
     * @param signers         Signature(s) to display
     * @param tsaTrustedCerts All trusted certs suitable for verifying TSA signatures
     * @param kseFrame        Reference to main class with currently opened keystores and their contents
     */
    public DViewSignature(Window parent, String title, CMSSignedData signedData,
            Collection<KseSignerInformation> signers, Store<X509CertificateHolder> tsaTrustedCerts,
            KseFrame kseFrame) {
        super(parent, title, Dialog.ModalityType.MODELESS);
        this.kseFrame = kseFrame;
        this.signedData = signedData;
        this.tsaTrustedCerts = tsaTrustedCerts;
        initComponents(signers);
    }

    private void initComponents(Collection<KseSignerInformation> signers) {
        jlSigners = new JLabel(res.getString("DViewSignature.jlSigners.text"));

        jtrSigners = new JTree(createSignerNodes(signers));
        jtrSigners.setRowHeight(Math.max(18, jtrSigners.getRowHeight()));
        jtrSigners.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        ToolTipManager.sharedInstance().registerComponent(jtrSigners);
        jtrSigners.setCellRenderer(new SignerTreeCellRend());
        jtrSigners.setRootVisible(false);

        TreeNode topNode = (TreeNode) jtrSigners.getModel().getRoot();
        expandTree(jtrSigners, new TreePath(topNode));

        jspSigners = PlatformUtil.createScrollPane(jtrSigners, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                     ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspSigners.setPreferredSize(new Dimension(100, 75));

        jlStatus = new JLabel(res.getString("DViewSignature.jlStatus.text"));

        jtfStatus = new JTextField(40);
        jtfStatus.setEditable(false);
        jtfStatus.setToolTipText(res.getString("DViewSignature.jtfStatus.tooltip"));

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

        jbTimeStamp = new JButton(res.getString("DViewSignature.jbTimeStamp.text"));
        jbTimeStamp.setToolTipText(res.getString("DViewSignature.jbTimeStamp.tooltip"));
        PlatformUtil.setMnemonic(jbTimeStamp, res.getString("DViewSignature.jbTimeStamp.mnemonic").charAt(0));

        jbSignerAsn1 = new JButton(res.getString("DViewSignature.jbSignerAsn1.text"));
        jbSignerAsn1.setToolTipText(res.getString("DViewSignature.jbSignerAsn1.tooltip"));
        PlatformUtil.setMnemonic(jbSignerAsn1, res.getString("DViewSignature.jbSignerAsn1.mnemonic").charAt(0));

        jbCertificates = new JButton(res.getString("DViewSignature.jbCertificates.text"));
        jbCertificates.setToolTipText(res.getString("DViewSignature.jbCertificates.tooltip"));
        PlatformUtil.setMnemonic(jbCertificates, res.getString("DViewSignature.jbCertificates.mnemonic").charAt(0));
        jbCertificates.setEnabled(!signedData.getCertificates().getMatches(null).isEmpty());

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
        pane.add(jlStatus, "");
        pane.add(jtfStatus, "sgx, wrap");
        pane.add(jlVersion, "");
        pane.add(jtfVersion, "wrap");
        pane.add(jlSubject, "");
        pane.add(jdnSubject, "wrap");
        pane.add(jlIssuer, "");
        pane.add(jdnIssuer, "wrap");
        pane.add(jlSigningTime, "");
        pane.add(jtfSigningTime, "wrap");
        pane.add(jlSignatureAlgorithm, "");
        pane.add(jtfSignatureAlgorithm, "wrap");
        pane.add(jbTimeStamp, "spanx, split");
        pane.add(jbSignerAsn1, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jbCertificates, "spanx, split");
        pane.add(jbPem, "");
        pane.add(jbAsn1, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jbOK, "spanx, tag ok");

        jtrSigners.addTreeSelectionListener(evt -> {
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

        jbSignerAsn1.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewSignature.this);
                signerAsn1DumpPressed();
            } finally {
                CursorUtil.setCursorFree(DViewSignature.this);
            }
        });

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

        // select (first) child in signers tree
        TreeNode firstChild = ((DefaultMutableTreeNode) topNode).getFirstChild();
        jtrSigners.setSelectionPath(new TreePath(new TreeNode[] {topNode, firstChild}));

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

    private DefaultMutableTreeNode createSignerNodes(Collection<KseSignerInformation> signers) {
        DefaultMutableTreeNode signersNode = new DefaultMutableTreeNode();

        for (SignerInformation signerInfo : signers) {
            DefaultMutableTreeNode signerNode = new DefaultMutableTreeNode(signerInfo);

            signersNode.add(signerNode);

            for (SignerInformation counterSignerInfo : signerInfo.getCounterSignatures().getSigners()) {
                signerNode.add(new DefaultMutableTreeNode(counterSignerInfo));
            }
        }

        return signersNode;
    }

    private void expandTree(JTree tree, TreePath parent) {
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() >= 0) {
            for (Enumeration<? extends TreeNode> enumNodes = node.children(); enumNodes.hasMoreElements(); ) {
                TreeNode subNode = enumNodes.nextElement();
                TreePath path = parent.pathByAddingChild(subNode);
                expandTree(tree, path);
            }
        }

        tree.expandPath(parent);
    }

    private KseSignerInformation getSelectedSignerInfo() {
        TreePath[] selections = jtrSigners.getSelectionPaths();

        if (selections == null) {
            return null;
        }

        return (KseSignerInformation) ((DefaultMutableTreeNode) selections[0].getLastPathComponent()).getUserObject();
    }

    private void populateDetails() {
        KseSignerInformation signerInfo = getSelectedSignerInfo();

        if (signerInfo == null) {
            jdnSubject.setEnabled(false);
            jdnIssuer.setEnabled(false);
            jbTimeStamp.setEnabled(false);
            jbSignerAsn1.setEnabled(false);

            jtfStatus.setText("");
            jtfStatus.setToolTipText("");
            jtfVersion.setText("");
            jdnSubject.setDistinguishedName(null);
            jdnIssuer.setDistinguishedName(null);
            jtfSigningTime.setText("");
            jtfSignatureAlgorithm.setText("");
        } else {
            jdnSubject.setEnabled(true);
            jdnIssuer.setEnabled(true);
            jbSignerAsn1.setEnabled(true);

            Date signingTime = signerInfo.getSigningTime();
            X509CertificateHolder cert = signerInfo.getCertificate();

            // Don't verify the signature if there is no signed content. CmsUtil.loadSignature already
            // tried to find and load the detached content for verification purposes.
            CmsSignatureStatus status;
            if (signedData.getSignedContent() != null) {
                status = signerInfo.getStatus();
            } else {
                status = CmsSignatureStatus.NOT_VERIFIED;
            }

            jtfStatus.setText(status.getText());
            jtfStatus.setCaretPosition(0);
            jtfStatus.setToolTipText(status.getToolTip());

            jtfVersion.setText(Integer.toString(signerInfo.getVersion()));
            jtfVersion.setCaretPosition(0);

            if (cert != null) {
                jdnSubject.setEnabled(true);
                jdnSubject.setDistinguishedName(cert.getSubject());
            } else {
                jdnSubject.setEnabled(false);
            }

            jdnIssuer.setDistinguishedName(signerInfo.getSID().getIssuer());

            if (signingTime != null) {
                jtfSigningTime.setText(StringUtils.formatDate(signingTime));
            } else {
                jtfSigningTime.setText("");
            }
            jtfSigningTime.setCaretPosition(0);

            SignatureType signatureType = lookupSignatureType(signerInfo);
            if (signatureType != null) {
                jtfSignatureAlgorithm.setText(signatureType.friendly());
            } else {
                jtfSignatureAlgorithm.setText("");
            }
            jtfSignatureAlgorithm.setCaretPosition(0);

            timeStampSigner = getTimeStampSignature(signerInfo);

            if (timeStampSigner != null) {
                jbTimeStamp.setEnabled(true);
            } else {
                jbTimeStamp.setEnabled(false);
            }
        }
    }

    private static SignatureType lookupSignatureType(KseSignerInformation signerInfo) {
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

    /**
     * Extracts the time stamp token, if present, from the signature's unsigned
     * attributes.
     *
     * @param signerInfo The signer information.
     * @return The time stamp token as CMSSignedData, if present, else null.
     */
    private static CMSSignedData getTimeStampSignature(KseSignerInformation signerInfo) {

        CMSSignedData timeStampToken = null;
        ContentInfo timeStamp = signerInfo.getTimeStamp();

        if (timeStamp != null) {
            try {
                timeStampToken = new CMSSignedData(timeStamp);
            } catch (CMSException e) {
                // Users are not going to know what to do about an invalid time stamp token. The
                // entire signature file has already been loaded so it is unlikely that this
                // token is invalid. The signature verification logic will indicate if the time
                // could not be verified.
            }
        }

        return timeStampToken;
    }

    private void certificatesPressed() {
        try {
            List<X509Certificate> certs = X509CertUtil.convertCertificateHolders(
                    signedData.getCertificates().getMatches(null));
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
        KseSignerInformation signer = getSelectedSignerInfo();
        String shortName = signer.getShortName();

        // Use the trusted certs not managed per the user preferences setting for
        // the time stamp trusted certs.
        List<KseSignerInformation> timeStampSigners = CmsUtil.convertSignerInformations(
                timeStampSigner.getSignerInfos().getSigners(), tsaTrustedCerts,
                timeStampSigner.getCertificates());

        DViewSignature dViewSignature = new DViewSignature(this,
                MessageFormat.format(res.getString("DViewSignature.TimeStampSigner.Title"), shortName),
                timeStampSigner, timeStampSigners, tsaTrustedCerts, kseFrame);
        dViewSignature.setLocationRelativeTo(this);
        dViewSignature.setVisible(true);
    }

    private void signerAsn1DumpPressed() {
        KseSignerInformation signer = getSelectedSignerInfo();

        try {
            DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, signer.toASN1Structure());
            dViewAsn1Dump.setLocationRelativeTo(this);
            dViewAsn1Dump.setVisible(true);
        } catch (Asn1Exception | IOException e) {
            DError.displayError(this, e);
        }
    }

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
        try {
            DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, signedData);
            dViewAsn1Dump.setLocationRelativeTo(this);
            dViewAsn1Dump.setVisible(true);
        } catch (Asn1Exception | IOException e) {
            DError.displayError(this, e);
        }
    }

    private void okPressed() {
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
        CMSSignedData signedData = CmsSigner.sign(new File("build.gradle"), eeKeyPair.getPrivate(), certs, false,
                SignatureType.SHA256_RSA, null, null);
        @SuppressWarnings("unchecked")
        List<KseSignerInformation> signers = CmsUtil.convertSignerInformations(signedData.getSignerInfos().getSigners(),
                new JcaCertStore(Arrays.asList(certs)), signedData.getCertificates());

        DViewSignature dialog = new DViewSignature(new javax.swing.JFrame(), "Title", signedData, signers, null,
                new KseFrame());
        DialogViewer.run(dialog);
    }
}
