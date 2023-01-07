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
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.MessageFormat;
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

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.publickey.OpenSslPubUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JPublicKeyFingerprint;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.asn1.Asn1Exception;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a public key with the option to display its fields if
 * it is of a supported type.
 */
public class DViewPublicKey extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private JLabel jlAlgorithm;
    private JTextField jtfAlgorithm;
    private JLabel jlKeySize;
    private JTextField jtfKeySize;
    private JLabel jlFormat;
    private JTextField jtfFormat;
    private JLabel jlEncoded;
    private JTextArea jtaEncoded;
    private JScrollPane jspEncoded;
    private JLabel jlFingerprint;
    private JPublicKeyFingerprint jcfFingerprint;
    private JButton jbPem;
    private JButton jbFields;
    private JButton jbAsn1;
    private JButton jbOK;

    private PublicKey publicKey;

    /**
     * Creates a new DViewPublicKey dialog.
     *
     * @param parent    Parent frame
     * @param title     The dialog title
     * @param publicKey Public key to display
     * @throws CryptoException A problem was encountered getting the public key's details
     */
    public DViewPublicKey(JFrame parent, String title, PublicKey publicKey) throws CryptoException {
        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        this.publicKey = convertKey(publicKey);
        initComponents();
    }

    /**
     * Creates new DViewPublicKey dialog where the parent is a dialog.
     *
     * @param parent    Parent dialog
     * @param title     The dialog title
     * @param publicKey Public key to display
     * @throws CryptoException A problem was encountered getting the public key's details
     */
    public DViewPublicKey(JDialog parent, String title, PublicKey publicKey) throws CryptoException {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        this.publicKey = convertKey(publicKey);
        initComponents();
    }

    private PublicKey convertKey(PublicKey publicKey) throws CryptoException {
        // convert public key object from whatever class it currently is (depends on Java version) to a BC object
        byte[] publicKeyEncoded = publicKey.getEncoded();
        return OpenSslPubUtil.load(publicKeyEncoded);
    }

    private void initComponents() throws CryptoException {

        jlAlgorithm = new JLabel(res.getString("DViewPublicKey.jlAlgorithm.text"));

        jtfAlgorithm = new JTextField();
        jtfAlgorithm.setEditable(false);
        jtfAlgorithm.setToolTipText(res.getString("DViewPublicKey.jtfAlgorithm.tooltip"));

        jlKeySize = new JLabel(res.getString("DViewPublicKey.jlKeySize.text"));

        jtfKeySize = new JTextField();
        jtfKeySize.setEditable(false);
        jtfKeySize.setToolTipText(res.getString("DViewPublicKey.jtfKeySize.tooltip"));

        jlFormat = new JLabel(res.getString("DViewPublicKey.jlFormat.text"));

        jtfFormat = new JTextField();
        jtfFormat.setEditable(false);
        jtfFormat.setToolTipText(res.getString("DViewPublicKey.jtfFormat.tooltip"));

        jlEncoded = new JLabel(res.getString("DViewPublicKey.jlEncoded.text"));

        jtaEncoded = new JTextArea();
        jtaEncoded.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaEncoded.setBackground(jtfFormat.getBackground());
        jtaEncoded.setEditable(false);
        jtaEncoded.setLineWrap(true);
        jtaEncoded.setToolTipText(res.getString("DViewPublicKey.jtfEncoded.tooltip"));

        jspEncoded = PlatformUtil.createScrollPane(jtaEncoded, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                   ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jspEncoded.setBorder(jtfFormat.getBorder());

        jlFingerprint = new JLabel(res.getString("DViewCertificate.jlFingerprint.text"));

        jcfFingerprint = new JPublicKeyFingerprint(25);

        jbPem = new JButton(res.getString("DViewPublicKey.jbPem.text"));
        PlatformUtil.setMnemonic(jbPem, res.getString("DViewPublicKey.jbPem.mnemonic").charAt(0));
        jbPem.setToolTipText(res.getString("DViewPublicKey.jbPem.tooltip"));

        jbFields = new JButton(res.getString("DViewPublicKey.jbFields.text"));
        PlatformUtil.setMnemonic(jbFields, res.getString("DViewPublicKey.jbFields.mnemonic").charAt(0));
        jbFields.setToolTipText(res.getString("DViewPublicKey.jbFields.tooltip"));

        jbAsn1 = new JButton(res.getString("DViewPublicKey.jbAsn1.text"));
        PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewPublicKey.jbAsn1.mnemonic").charAt(0));
        jbAsn1.setToolTipText(res.getString("DViewPublicKey.jbAsn1.tooltip"));

        jbOK = new JButton(res.getString("DViewPublicKey.jbOK.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
        pane.add(jlAlgorithm, "");
        pane.add(jtfAlgorithm, "growx, pushx, wrap");
        pane.add(jlKeySize, "");
        pane.add(jtfKeySize, "growx, pushx, wrap");
        pane.add(jlFormat, "");
        pane.add(jtfFormat, "growx, pushx, wrap");
        pane.add(jlEncoded, "");
        pane.add(jspEncoded, "growx, height 150lp:150lp:150lp, wrap");
        pane.add(jlFingerprint, "");
        pane.add(jcfFingerprint, "wrap");
        pane.add(jbPem, "spanx, split");
        pane.add(jbFields, "");
        pane.add(jbAsn1, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jbOK, "spanx, tag ok");

        // actions

        jbOK.addActionListener(evt -> okPressed());

        jbPem.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewPublicKey.this);
                pemEncodingPressed();
            } finally {
                CursorUtil.setCursorFree(DViewPublicKey.this);
            }
        });

        jbFields.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewPublicKey.this);
                fieldsPressed();
            } finally {
                CursorUtil.setCursorFree(DViewPublicKey.this);
            }
        });

        jbAsn1.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewPublicKey.this);
                asn1DumpPressed();
            } finally {
                CursorUtil.setCursorFree(DViewPublicKey.this);
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

    private void populateDialog() throws CryptoException {
        KeyInfo keyInfo = KeyPairUtil.getKeyInfo(publicKey);

        jtfAlgorithm.setText(keyInfo.getAlgorithm());

        if (publicKey instanceof ECPublicKey) {
            jtfAlgorithm.setText(jtfAlgorithm.getText() + " (" + keyInfo.getDetailedAlgorithm() + ")");
        }

        Integer keyLength = keyInfo.getSize();

        if (keyLength != null) {
            jtfKeySize.setText(MessageFormat.format(res.getString("DViewPublicKey.jtfKeySize.text"), "" + keyLength));
        } else {
            jtfKeySize.setText(MessageFormat.format(res.getString("DViewPublicKey.jtfKeySize.text"), "?"));
        }

        jtfFormat.setText(publicKey.getFormat());

        jtaEncoded.setText(new BigInteger(1, publicKey.getEncoded()).toString(16).toUpperCase());
        jtaEncoded.setCaretPosition(0);

        jcfFingerprint.setPublicKey(publicKey);

        jbFields.setEnabled((publicKey instanceof RSAPublicKey) || (publicKey instanceof DSAPublicKey) ||
                            (publicKey instanceof ECPublicKey) || (publicKey instanceof BCEdDSAPublicKey));
    }

    private void pemEncodingPressed() {
        try {
            DViewPem dViewCsrPem = new DViewPem(this, res.getString("DViewPublicKey.Pem.Title"), publicKey);
            dViewCsrPem.setLocationRelativeTo(this);
            dViewCsrPem.setVisible(true);
        } catch (CryptoException e) {
            DError.displayError(this, e);
        }
    }

    private void fieldsPressed() {
        DViewAsymmetricKeyFields dViewAsymmetricKeyFields = new DViewAsymmetricKeyFields(this, publicKey);
        dViewAsymmetricKeyFields.setLocationRelativeTo(this);
        dViewAsymmetricKeyFields.setVisible(true);
    }

    private void asn1DumpPressed() {
        try {
            DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, publicKey);
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

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", KSE.BC);
        KeyPair keyPair = keyGen.genKeyPair();

        DViewPublicKey dialog = new DViewPublicKey(new javax.swing.JFrame(), "Title", keyPair.getPublic());
        DialogViewer.run(dialog);
    }
}
