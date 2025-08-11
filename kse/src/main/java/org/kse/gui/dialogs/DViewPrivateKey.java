/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.MessageFormat;
import java.util.Optional;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.privatekey.PrivateKeyFormat;
import org.kse.gui.CursorUtil;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.crypto.privatekey.PrivateKeyUtils;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyType;
import org.kse.gui.error.DError;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.asn1.Asn1Exception;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a private key with the option to display its fields
 * if it is of a supported type (RSA or DSA).
 */
public class DViewPrivateKey extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");
    private static final ResourceBundle resActions = ResourceBundle.getBundle("org/kse/gui/actions/resources");

    public static final int MAX_LINE_LENGTH = 32;

    private JLabel jlAlgorithm;
    private JTextField jtfAlgorithm;
    private JLabel jlKeySize;
    private JTextField jtfKeySize;
    private JLabel jlFormat;
    private JTextField jtfFormat;
    private JLabel jlEncoded;
    private JTextArea jtaEncoded;
    private JScrollPane jspEncoded;
    private JButton jbExport;
    private JButton jbGenCert;
    private JButton jbPem;
    private JButton jbFields;
    private JButton jbAsn1;
    private JButton jbOK;

    private String alias;
    private PrivateKey privateKey;

    private KsePreferences preferences;

    private Optional<PrivateKeyFormat> format;

    private String fileNewCert;
    
    /**
     * Creates a new DViewPrivateKey dialog.
     *
     * @param parent     Parent frame
     * @param title      The dialog title
     * @param privateKey Private key to display
     * @throws CryptoException A problem was encountered getting the private key's details
     */
    public DViewPrivateKey(JFrame parent, String title, String alias, PrivateKey privateKey, KsePreferences preferences, Optional<PrivateKeyFormat> format)
            throws CryptoException {
        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        this.alias = alias;
        this.privateKey = privateKey;
        this.preferences = preferences;
        this.format = format;
        initComponents(false);
    }

    /**
     * Creates new DViewPrivateKey dialog where the parent is a dialog.
     *
     * @param parent     Parent dialog
     * @param title      The dialog title
     * @param privateKey Private key to display
     * @throws CryptoException A problem was encountered getting the private key's details
     */
    public DViewPrivateKey(JDialog parent, String title, PrivateKey privateKey) throws CryptoException {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        this.privateKey = privateKey;
        this.format = Optional.empty();
        initComponents(true);
        jbExport.setVisible(false);
    }

    private void initComponents(boolean generateVisible) throws CryptoException {

        jlAlgorithm = new JLabel(res.getString("DViewPrivateKey.jlAlgorithm.text"));

        jtfAlgorithm = new JTextField();
        jtfAlgorithm.setEditable(false);
        jtfAlgorithm.setToolTipText(res.getString("DViewPrivateKey.jtfAlgorithm.tooltip"));

        jlKeySize = new JLabel(res.getString("DViewPrivateKey.jlKeySize.text"));

        jtfKeySize = new JTextField();
        jtfKeySize.setEditable(false);
        jtfKeySize.setToolTipText(res.getString("DViewPrivateKey.jtfKeySize.tooltip"));

        jlFormat = new JLabel(res.getString("DViewPrivateKey.jlFormat.text"));

        jtfFormat = new JTextField();
        jtfFormat.setEditable(false);
        jtfFormat.setToolTipText(res.getString("DViewPrivateKey.jtfFormat.tooltip"));

        jlEncoded = new JLabel(res.getString("DViewPrivateKey.jlEncoded.text"));

        jtaEncoded = new JTextArea();
        jtaEncoded.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaEncoded.setBackground(jtfFormat.getBackground());
        jtaEncoded.setEditable(false);
        jtaEncoded.setLineWrap(true);
        jtaEncoded.setToolTipText(res.getString("DViewPrivateKey.jtfEncoded.tooltip"));

        jspEncoded = PlatformUtil.createScrollPane(jtaEncoded, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                   ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jspEncoded.setBorder(jtfFormat.getBorder());

        jbExport = new JButton(res.getString("DViewPrivateKey.jbExport.text"));
        PlatformUtil.setMnemonic(jbExport, res.getString("DViewPrivateKey.jbExport.mnemonic").charAt(0));
        jbExport.setToolTipText(res.getString("DViewPrivateKey.jbExport.tooltip"));

        jbGenCert = new JButton(res.getString("DViewPrivateKey.jbGenCert.text"));
        PlatformUtil.setMnemonic(jbGenCert, res.getString("DViewPrivateKey.jbGenCert.mnemonic").charAt(0));
        jbGenCert.setToolTipText(res.getString("DViewPrivateKey.jbGenCert.tooltip"));
        
        jbPem = new JButton(res.getString("DViewPrivateKey.jbPem.text"));
        PlatformUtil.setMnemonic(jbPem, res.getString("DViewPrivateKey.jbPem.mnemonic").charAt(0));
        jbPem.setToolTipText(res.getString("DViewPrivateKey.jbPem.tooltip"));

        jbFields = new JButton(res.getString("DViewPrivateKey.jbFields.text"));
        PlatformUtil.setMnemonic(jbFields, res.getString("DViewPrivateKey.jbFields.mnemonic").charAt(0));
        jbFields.setToolTipText(res.getString("DViewPrivateKey.jbFields.tooltip"));

        jbAsn1 = new JButton(res.getString("DViewPrivateKey.jbAsn1.text"));
        PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewPrivateKey.jbAsn1.mnemonic").charAt(0));
        jbAsn1.setToolTipText(res.getString("DViewPrivateKey.jbAsn1.tooltip"));

        jbOK = new JButton(res.getString("DViewPrivateKey.jbOK.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog", "[right]unrel[]", "[]unrel[]"));
        pane.add(jlAlgorithm, "");
        pane.add(jtfAlgorithm, "growx, pushx, wrap");
        pane.add(jlKeySize, "");
        pane.add(jtfKeySize, "growx, pushx, wrap");
        pane.add(jlFormat, "");
        pane.add(jtfFormat, "growx, pushx, wrap");
        pane.add(jlEncoded, "");
        pane.add(jspEncoded, "width 300lp:300lp:300lp, height 100lp:100lp:100lp, wrap");

        if (generateVisible) {
            pane.add(jbGenCert, "spanx, split");
        } else {
            pane.add(jbExport, "spanx, split");
        }
        pane.add(jbPem, "");
        pane.add(jbFields, "");
        pane.add(jbAsn1, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap unrel:push");
        pane.add(jbOK, "spanx, tag ok");

        // actions

        jbExport.addActionListener(evt -> exportPressed());
        jbGenCert.addActionListener(evt -> generatePressed());

        jbOK.addActionListener(evt -> okPressed());

        jbPem.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewPrivateKey.this);
                pemEncodingPressed();
            } finally {
                CursorUtil.setCursorFree(DViewPrivateKey.this);
            }
        });

        jbFields.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewPrivateKey.this);
                fieldsPressed();
            } finally {
                CursorUtil.setCursorFree(DViewPrivateKey.this);
            }
        });

        jbAsn1.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewPrivateKey.this);
                asn1DumpPressed();
            } finally {
                CursorUtil.setCursorFree(DViewPrivateKey.this);
            }
        });

        setResizable(false);

        populateDialog();

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

    private void generatePressed() {
        try {
            KeyInfo keyInfo = KeyPairUtil.getKeyInfo(privateKey);
            KeyPairType keyPairType = null;
            KeyPair keyPair = null;
            
            if (privateKey instanceof RSAPrivateKey) {
                RSAPrivateCrtKey rsaPrivate = (RSAPrivateCrtKey) privateKey;
                RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(rsaPrivate.getModulus(),
                        rsaPrivate.getPublicExponent());
                KeyFactory kf = KeyFactory.getInstance("RSA", KSE.BC);
                PublicKey publicKey = kf.generatePublic(publicSpec);
                keyPair = new KeyPair(publicKey, privateKey);
                keyPairType = KeyPairType.RSA;
            }
            if (privateKey instanceof ECPrivateKey) {
                ECPrivateKey ecPrivate = (ECPrivateKey) privateKey;
                BigInteger d = ecPrivate.getS();
                ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(keyInfo.getDetailedAlgorithm());
                ECPoint Q = ecSpec.getG().multiply(d).normalize();
                ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(Q, ecSpec);
                KeyFactory keyFactory = KeyFactory.getInstance("EC", KSE.BC);
                PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
                keyPair = new KeyPair(publicKey, privateKey);
                keyPairType = KeyPairType.EC;
            }
            if (privateKey instanceof DSAPrivateKey) {
                DSAPrivateKey dsaPrivate = (DSAPrivateKey) privateKey;
                DSAParams params = dsaPrivate.getParams();
                BigInteger y = params.getG().modPow(dsaPrivate.getX(), params.getP());
                DSAPublicKeySpec publicSpec = new DSAPublicKeySpec(y, params.getP(), params.getQ(), params.getG());
                KeyFactory kf = KeyFactory.getInstance("DSA", KSE.BC);
                PublicKey publicKey = kf.generatePublic(publicSpec);
                keyPair = new KeyPair(publicKey, privateKey);
                keyPairType = KeyPairType.DSA;
            }
            if (privateKey instanceof EdDSAPrivateKey) {
                EdDSAPrivateKey edPrivate = (EdDSAPrivateKey) privateKey;
                byte[] pubKeyBytes = edPrivate.getPublicKey().getEncoded();
                KeyFactory kf = KeyFactory.getInstance(edPrivate.getAlgorithm(), KSE.BC);
                PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(pubKeyBytes));
                keyPair = new KeyPair(publicKey, privateKey);
                switch (edPrivate.getAlgorithm()) {
                case "Ed25519":
                    keyPairType = KeyPairType.ED25519;
                    break;
                case "Ed448":
                    keyPairType = KeyPairType.ED448;
                    break;
                default:
                    keyPairType = KeyPairType.EDDSA;
                }
            }
            if (privateKey instanceof MLDSAPrivateKey) {
                MLDSAPrivateKey mldsaPrivate = (MLDSAPrivateKey) privateKey;
                PublicKey publicKey = mldsaPrivate.getPublicKey();
                keyPair = new KeyPair(publicKey, privateKey);
                switch (mldsaPrivate.getAlgorithm()) {
                case "ML-DSA-44":
                    keyPairType = KeyPairType.MLDSA44;
                    break;
                case "ML-DSA-65":
                    keyPairType = KeyPairType.MLDSA65;
                    break;
                case "ML-DSA-87":
                    keyPairType = KeyPairType.MLDSA87;
                    break;
                default:
                }
            }
            if (keyPair != null && keyPairType != null) {
                DGenerateKeyPairCert dGenerateKeyPairCert = new DGenerateKeyPairCert(null, null,
                        res.getString("DViewPrivateKey.dGenerateKeyPairCert.text"), keyPair,
                        keyPairType, null, null, KSE.BC);
                dGenerateKeyPairCert.setLocationRelativeTo((JDialog) this.getParent());
                dGenerateKeyPairCert.setVisible(true);
                X509Certificate certificate = dGenerateKeyPairCert.getCertificate();
                if (certificate != null) {
                    File tempFile = File.createTempFile("gen-", ".cer");
                    tempFile.deleteOnExit();
                    try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                        fos.write(certificate.getEncoded());
                    }
                    fileNewCert = tempFile.getAbsolutePath();
                    closeDialog();
                }
            }
        } catch (Exception ex) {
            DError.displayError((JFrame) this.getParent(), ex);
        }
    }

    private void exportPressed() {
        try {
            DExportPrivateKeyType dExportPrivateKeyType = new DExportPrivateKeyType((JFrame) this.getParent(), privateKey);
            dExportPrivateKeyType.setLocationRelativeTo(null);
            dExportPrivateKeyType.setVisible(true);

            if (!dExportPrivateKeyType.exportTypeSelected()) {
                return;
            }
            if (dExportPrivateKeyType.exportPkcs8()) {
                PrivateKeyUtils.exportAsPkcs8(privateKey, alias, (JFrame) this.getParent(), preferences, resActions);
            } else if (dExportPrivateKeyType.exportPvk()) {
                PrivateKeyUtils.exportAsPvk(privateKey, alias, (JFrame) this.getParent(), preferences, resActions);
            } else if (dExportPrivateKeyType.exportOpenSsl()) {
                PrivateKeyUtils.exportAsOpenSsl(privateKey, alias, (JFrame) this.getParent(), preferences, resActions);
            } else if (dExportPrivateKeyType.exportJwk()) {
                PrivateKeyUtils.exportAsJwk(privateKey, alias, (JFrame) this.getParent(), preferences, resActions);
            }
        } catch (Exception ex) {
            DError.displayError((JFrame) this.getParent(), ex);
        }

    }

    private void populateDialog() throws CryptoException {
        KeyInfo keyInfo = KeyPairUtil.getKeyInfo(privateKey);

        jtfAlgorithm.setText(keyInfo.getAlgorithm());

        if (privateKey instanceof ECPrivateKey) {
            jtfAlgorithm.setText(jtfAlgorithm.getText() + " (" + keyInfo.getDetailedAlgorithm() + ")");
        }

        Integer keyLength = keyInfo.getSize();

        if (keyLength != null) {
            jtfKeySize.setText(MessageFormat.format(res.getString("DViewPrivateKey.jtfKeySize.text"), "" + keyLength));
        } else {
            jtfKeySize.setText(MessageFormat.format(res.getString("DViewPrivateKey.jtfKeySize.text"), "?"));
        }

        jtfFormat.setText(format.map(PrivateKeyFormat::getValue).orElse(privateKey.getFormat()));

        jtaEncoded.setText(new BigInteger(1, privateKey.getEncoded()).toString(16).toUpperCase());
        jtaEncoded.setCaretPosition(0);

        jbFields.setEnabled((privateKey instanceof RSAPrivateKey) || (privateKey instanceof DSAPrivateKey)
                || (privateKey instanceof ECPrivateKey) || (privateKey instanceof EdDSAPrivateKey)
                || (privateKey instanceof MLDSAPrivateKey));
    }

    private void pemEncodingPressed() {
        try {
            DViewPem dViewCsrPem = new DViewPem(this, res.getString("DViewPrivateKey.Pem.Title"), privateKey);
            dViewCsrPem.setLocationRelativeTo(this);
            dViewCsrPem.setVisible(true);
        } catch (CryptoException e) {
            DError.displayError(this, e);
        }
    }

    private void fieldsPressed() {
        DViewAsymmetricKeyFields dViewAsymmetricKeyFields = new DViewAsymmetricKeyFields(this, privateKey);
        dViewAsymmetricKeyFields.setLocationRelativeTo(this);
        dViewAsymmetricKeyFields.setVisible(true);
    }

    private void asn1DumpPressed() {
        try {
            DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, privateKey);
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

    public String getFileNewCert() {
        return fileNewCert;
    }

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", KSE.BC);
        KeyPair keyPair = keyGen.genKeyPair();

        PrivateKey privKey = keyPair.getPrivate();
        DViewPrivateKey dialog = new DViewPrivateKey(new javax.swing.JFrame(), "Title", "private", privKey, null, Optional.empty());
        DialogViewer.run(dialog);
    }
}
