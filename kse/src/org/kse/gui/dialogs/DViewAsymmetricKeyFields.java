/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2022 Kai Kramer
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
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.HexUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the fields of a asymmetric key.
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
            BCEdDSAPublicKey bcEdDSAPublicKey = (BCEdDSAPublicKey) key;
            String edAlg = bcEdDSAPublicKey.getAlgorithm(); // Ed25519 or Ed448
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PublicKey.title"), edAlg);
        } else if (key instanceof BCEdDSAPrivateKey) {
            BCEdDSAPrivateKey bcEdDSAPrivateKey = (BCEdDSAPrivateKey) key;
            String edAlg = bcEdDSAPrivateKey.getAlgorithm(); // Ed25519 or Ed448
            return MessageFormat.format(res.getString("DViewAsymmetricKeyFields.PrivateKey.title"), edAlg);
        }
        throw new IllegalArgumentException("Unsupported key format for asymmetric fields viewer");
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
            RSAPublicKey rsaPub = (RSAPublicKey) key;

            fields = new Field[] {
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubRsaPublicExponent.text"),
                              rsaPub.getPublicExponent()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubRsaModulus.text"),
                              rsaPub.getModulus()) };
        } else if (key instanceof DSAPublicKey) {
            DSAPublicKey dsaPub = (DSAPublicKey) key;
            DSAParams dsaParams = dsaPub.getParams();

            fields = new Field[] {
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaPrimeModulusP.text"),
                              dsaParams.getP()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaPrimeQ.text"), dsaParams.getQ()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaGeneratorG.text"),
                              dsaParams.getG()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaPublicKeyY.text"),
                              dsaPub.getY()) };
        } else if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaPvk = (RSAPrivateCrtKey) key;

            fields = new Field[] {
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPublicExponent.text"),
                              rsaPvk.getPublicExponent()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaModulus.text"),
                              rsaPvk.getModulus()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeP.text"),
                              rsaPvk.getPrimeP()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeQ.text"),
                              rsaPvk.getPrimeQ()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeExponentP.text"),
                              rsaPvk.getPrimeExponentP()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeExponentQ.text"),
                              rsaPvk.getPrimeExponentQ()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaCrtCoefficient.text"),
                              rsaPvk.getCrtCoefficient()),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrivateExponent.text"),
                              rsaPvk.getPrivateExponent()) };
        } else if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rsaPvk = (RSAPrivateKey) key;

            fields = new Field[] { new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaModulus.text"),
                                             rsaPvk.getModulus()), new Field(
                    res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrivateExponent.text"),
                    rsaPvk.getPrivateExponent()) };
        } else if (key instanceof DSAPrivateKey) {
            DSAPrivateKey dsaPvk = (DSAPrivateKey) key;
            DSAParams dsaParams = dsaPvk.getParams();

            BigInteger p = dsaParams.getP();
            BigInteger q = dsaParams.getQ();
            BigInteger g = dsaParams.getG();
            BigInteger x = dsaPvk.getX();

            fields = new Field[] {
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaPrimeModulusP.text"), p),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaPrimeQ.text"), q),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaGeneratorG.text"), g),
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaSecretExponentX.text"), x) };
        } else if (key instanceof ECPrivateKey) {
            ECPrivateKey ecPrivateKey = (ECPrivateKey) key;
            BigInteger s = ecPrivateKey.getS();

            fields = new Field[] {
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivEcPrivateKey.text"), s)
            };
        } else if (key instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) key;
            BigInteger x = ecPublicKey.getW().getAffineX();
            BigInteger y = ecPublicKey.getW().getAffineY();

            fields = new Field[] { new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubEcAffineX.text"), x),
                                   new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubEcAffineY.text"), y)
            };
        } else if (key instanceof BCEdDSAPrivateKey) {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(key.getEncoded());

            // RFC 8410 defines that the EdDSA private key is wrapped in another OCTET STRING...
            ASN1OctetString curvePrivateKey = ASN1OctetString.getInstance(privateKeyInfo.getPrivateKey().getOctets());
            BigInteger rawKey = new BigInteger(curvePrivateKey.getOctets());

            fields = new Field[] {
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivEdPrivateKey.text"), rawKey)
            };
        } else if (key instanceof BCEdDSAPublicKey) {
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(key.getEncoded());
            BigInteger rawKey = new BigInteger(subjectPublicKeyInfo.getPublicKeyData().getOctets());

            fields = new Field[] {
                    new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubEdKey.text"), rawKey)
            };
        }

        if (fields != null) {
            jltFields.setListData(fields);
            jltFields.setSelectedIndex(0);
        }
    }

    private void updateFieldValue() {
        int selectedRow = jltFields.getSelectedIndex();

        if (selectedRow == -1) {
            jtaFieldValue.setText("");
        } else {
            Field field = jltFields.getSelectedValue();

            jtaFieldValue.setText(HexUtil.getHexString(field.getValue(), "", 0, MAX_LINE_LENGTH));
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
        private BigInteger value;

        public Field(String name, BigInteger value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public BigInteger getValue() {
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

//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
//        KeyPair keyPair = keyGen.genKeyPair();

//        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
//        keyGen.initialize(ecSpec);
//        KeyPair keyPair = keyGen.generateKeyPair();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair keyPair = keyGen.generateKeyPair();

        DViewAsymmetricKeyFields dialog = new DViewAsymmetricKeyFields(new JDialog(), keyPair.getPrivate());
        DialogViewer.run(dialog);
    }
}
