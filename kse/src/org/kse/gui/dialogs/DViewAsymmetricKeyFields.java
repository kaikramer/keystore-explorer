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
package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.util.BigIntegers;
import org.kse.KSE;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.HexUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the fields of an asymmetric key.
 */
public class DViewAsymmetricKeyFields extends JEscDialog {
    private static final long serialVersionUID = 1L;

    public static final int MAX_LINE_LENGTH = 32;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private JLabel jlFields;
    private JList<Field> jltFields;
    private JLabel jlFieldValue;
    private JScrollPane jspFieldValue;
    private JTextArea jtaFieldValue;
    private JButton jbOK;

    private Key key;

    /**
     * Creates new DViewAsymmetricKeyFields dialog.
     *
     * @param parent       Parent dialog
     * @param key          RSA/DSA/EC public or private key to display fields of
     */
    public DViewAsymmetricKeyFields(JDialog parent, Key key) {
        super(parent, getTitle(key), Dialog.ModalityType.DOCUMENT_MODAL);
        this.key = key;
        initFields();
    }

    private static String getTitle(Key key) {
        if (key instanceof RSAPublicKey) {
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PublicKey.title"), "RSA");
        } else if (key instanceof RSAPrivateKey) {
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PrivateKey.title"), "RSA");
        } else if (key instanceof DSAPublicKey) {
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PublicKey.title"), "DSA");
        } else if (key instanceof DSAPrivateKey) {
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PrivateKey.title"), "DSA");
        } else if (key instanceof ECPublicKey) {
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PublicKey.title"), "EC");
        } else if (key instanceof ECPrivateKey) {
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PrivateKey.title"), "EC");
        } else if (key instanceof BCEdDSAPublicKey) {
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PublicKey.title"), getEdAlg(key));
        } else if (key instanceof BCEdDSAPrivateKey) {
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PrivateKey.title"), getEdAlg(key));
        }
        throw new IllegalArgumentException("Unsupported key format for asymmetric fields viewer");
    }

    private static String getEdAlg(Key key) {
        // Ed25519 or Ed448?
        String edAlg;
        if (key instanceof BCEdDSAPublicKey) {
            BCEdDSAPublicKey bcEdDSAPublicKey = (BCEdDSAPublicKey) key;
            edAlg = bcEdDSAPublicKey.getAlgorithm(); // Ed25519 or Ed448
        } else {
            BCEdDSAPrivateKey bcEdDSAPrivateKey = (BCEdDSAPrivateKey) key;
            edAlg = bcEdDSAPrivateKey.getAlgorithm();
        }
        return edAlg;
    }

    private void initFields() {
        jlFields = new JLabel(res.getString("DViewAsymmetricKeyFields.jlFields.text"));

        jltFields = new JList<>();
        jltFields.setToolTipText(res.getString("DViewAsymmetricKeyFields.jltFields.tooltip"));
        jltFields.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        jltFields.setBorder(new EtchedBorder());

        jltFields.addListSelectionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewAsymmetricKeyFields.this);
                updateFieldValue();
            } finally {
                CursorUtil.setCursorFree(DViewAsymmetricKeyFields.this);
            }
        });

        jlFieldValue = new JLabel(res.getString("DViewAsymmetricKeyFields.jlFieldValue.text"));

        jtaFieldValue = new JTextArea();
        jtaFieldValue.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaFieldValue.setEditable(false);
        jtaFieldValue.setToolTipText(res.getString("DViewAsymmetricKeyFields.jtaFieldValue.tooltip"));

        jspFieldValue = PlatformUtil.createScrollPane(jtaFieldValue, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                      ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspFieldValue.setPreferredSize(new Dimension(300, 200));

        jbOK = new JButton(res.getString("DViewAsymmetricKeyFields.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        populateFields();

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]unrel[]", "[]rel[]"));
        pane.add(jlFields, "");
        pane.add(jlFieldValue, "wrap");
        pane.add(jltFields, "grow");
        pane.add(jspFieldValue, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jbOK, "spanx, tag ok");

        setResizable(false);

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

    private void populateFields() {
        Field[] fields = null;

        if (key instanceof RSAPublicKey) {
            fields = getRsaPubFields();
        } else if (key instanceof RSAPrivateCrtKey) {
            fields = getRsaPrivateCrtFields();
        } else if (key instanceof RSAPrivateKey) {
            fields = getRsaPrivateFields();
        } else if (key instanceof DSAPublicKey) {
            fields = getDsaPubFields();
        } else if (key instanceof DSAPrivateKey) {
            fields = getDsaPrivateFields();
        } else if (key instanceof ECPublicKey) {
            fields = getEcPubFields();
        } else if (key instanceof ECPrivateKey) {
            fields = getEcPrivateFields();
        } else if (key instanceof BCEdDSAPublicKey) {
            fields = getEdPubFields();
        } else if (key instanceof BCEdDSAPrivateKey) {
            fields = getEdPrivateFields();
        }

        if (fields != null) {
            jltFields.setListData(fields);
            jltFields.setSelectedIndex(0);
        }
    }

    private Field[] getRsaPubFields() {
        Field[] fields;
        RSAPublicKey rsaPub = (RSAPublicKey) key;

        String modulus = getHexString(rsaPub.getModulus());
        String exponent = getHexString(rsaPub.getPublicExponent());

        fields = new Field[] {
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubRsaModulus.text"), modulus),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubRsaPublicExponent.text"), exponent) };
        return fields;
    }

    private Field[] getRsaPrivateFields() {
        Field[] fields;
        RSAPrivateKey rsaPvk = (RSAPrivateKey) key;

        String modulus = getHexString(rsaPvk.getModulus());
        String exponent = getHexString(rsaPvk.getPrivateExponent());

        fields = new Field[] {
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaModulus.text"), modulus),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrivateExponent.text"), exponent) };
        return fields;
    }

    private Field[] getRsaPrivateCrtFields() {
        Field[] fields;
        RSAPrivateCrtKey rsaPvk = (RSAPrivateCrtKey) key;

        String pubExp = getHexString(rsaPvk.getPublicExponent());
        String modulus = getHexString(rsaPvk.getModulus());
        String primeP = getHexString(rsaPvk.getPrimeP());
        String primeQ = getHexString(rsaPvk.getPrimeQ());
        String primeExpP = getHexString(rsaPvk.getPrimeExponentP());
        String primeExpQ = getHexString(rsaPvk.getPrimeExponentQ());
        String crtCoeff = getHexString(rsaPvk.getCrtCoefficient());
        String privExp = getHexString(rsaPvk.getPrivateExponent());

        fields = new Field[] {
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPublicExponent.text"), pubExp),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaModulus.text"), modulus),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeP.text"), primeP),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeQ.text"), primeQ),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeExponentP.text"), primeExpP),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeExponentQ.text"), primeExpQ),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaCrtCoefficient.text"), crtCoeff),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrivateExponent.text"), privExp) };
        return fields;
    }

    private Field[] getDsaPubFields() {
        Field[] fields;
        DSAPublicKey dsaPub = (DSAPublicKey) key;
        DSAParams dsaParams = dsaPub.getParams();

        String p = getHexString(dsaParams.getP());
        String q = getHexString(dsaParams.getQ());
        String g = getHexString(dsaParams.getG());
        String y = getHexString(dsaPub.getY());

        fields = new Field[] {
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaPrimeModulusP.text"), p),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaPrimeQ.text"), q),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaGeneratorG.text"), g),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaPublicKeyY.text"), y) };
        return fields;
    }

    private Field[] getDsaPrivateFields() {
        Field[] fields;
        DSAPrivateKey dsaPvk = (DSAPrivateKey) key;
        DSAParams dsaParams = dsaPvk.getParams();

        String p = getHexString(dsaParams.getP());
        String q = getHexString(dsaParams.getQ());
        String g = getHexString(dsaParams.getG());
        String x = getHexString(dsaPvk.getX());

        fields = new Field[] {
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaPrimeModulusP.text"), p),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaPrimeQ.text"), q),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaGeneratorG.text"), g),
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaSecretExponentX.text"), x) };
        return fields;
    }

    private Field[] getEcPubFields() {
        Field[] fields;
        ECPublicKey ecPublicKey = (ECPublicKey) key;

        String x = getHexString(BigIntegers.asUnsignedByteArray(ecPublicKey.getW().getAffineX()));
        String y = getHexString(BigIntegers.asUnsignedByteArray(ecPublicKey.getW().getAffineY()));

        fields = new Field[] { new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubEcAffineX.text"), x),
                               new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubEcAffineY.text"), y) };
        return fields;
    }

    private Field[] getEcPrivateFields() {
        Field[] fields;
        ECPrivateKey ecPrivateKey = (ECPrivateKey) key;

        String s = getHexString(BigIntegers.asUnsignedByteArray(ecPrivateKey.getS()));

        fields = new Field[] {
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivEcPrivateKey.text"), s) };
        return fields;
    }

    private Field[] getEdPubFields() {
        Field[] fields;
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(key.getEncoded());

        byte[] rawKey = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        String rawKeyHex = getHexString(rawKey);

        fields = new Field[] {
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubEdKey.text"), rawKeyHex) };
        return fields;
    }

    private Field[] getEdPrivateFields() {
        Field[] fields;
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(key.getEncoded());

        // RFC 8410 defines that the EdDSA private key is wrapped in another OCTET STRING...
        ASN1OctetString curvePrivateKey = ASN1OctetString.getInstance(privateKeyInfo.getPrivateKey().getOctets());
        String rawKeyHex = getHexString(curvePrivateKey.getOctets());

        fields = new Field[] {
                new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivEdPrivateKey.text"), rawKeyHex) };
        return fields;
    }

    private static String getHexString(BigInteger bigInt) {
        return HexUtil.getHexString(bigInt, "", 0, MAX_LINE_LENGTH);
    }

    private static String getHexString(byte[] bytes) {
        return HexUtil.getHexString(bytes, "", 0, MAX_LINE_LENGTH);
    }

    private void updateFieldValue() {
        int selectedRow = jltFields.getSelectedIndex();

        if (selectedRow == -1) {
            jtaFieldValue.setText("");
        } else {
            Field field = jltFields.getSelectedValue();

            jtaFieldValue.setText(field.getValue());
            jtaFieldValue.setCaretPosition(0);
        }
    }

    private void okPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    private static class Field {
        private String name;
        private String value;

        public Field(String name, String value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        @Override
        public String toString() {
            return getName();
        }
    }

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();

//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", KSE.BC);
//        KeyPair keyPair = keyGen.genKeyPair();

//        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", KSE.BC);
//        keyGen.initialize(ecSpec);
//        KeyPair keyPair = keyGen.generateKeyPair();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", KSE.BC);
        KeyPair keyPair = keyGen.generateKeyPair();

        DViewAsymmetricKeyFields dialog = new DViewAsymmetricKeyFields(new JDialog(), keyPair.getPrivate());
        DialogViewer.run(dialog);
    }
}
