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
package org.kse.gui.crypto;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.asn1.x500.X500Name;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.PublicKeyFingerprintAlgorithm;
import org.kse.crypto.digest.PublicKeyFingerprintUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X509CertificateGenerator;
import org.kse.crypto.x509.X509CertificateVersion;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.HexUtil;

/**
 * Dialog to view a certificate fingerprint.
 */
public class DViewPublicKeyFingerprint extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

    private JPanel jpButtons;
    private JButton jbCopy;
    private JButton jbOK;
    private JPanel jpFingerprint;
    private JScrollPane jspPolicy;
    private JTextArea jtaFingerprint;

    private PublicKey publicKey;
    private PublicKeyFingerprintAlgorithm fingerprintAlg;

    /**
     * Creates a new DViewPublicKeyFingerprint dialog.
     *
     * @param parent         The parent frame
     * @param publicKey      Public key to fingerprint
     * @param fingerprintAlg Fingerprint algorithm
     */
    public DViewPublicKeyFingerprint(JFrame parent, PublicKey publicKey, PublicKeyFingerprintAlgorithm fingerprintAlg) {
        super(parent, ModalityType.DOCUMENT_MODAL);
        this.publicKey = publicKey;
        this.fingerprintAlg = fingerprintAlg;
        initComponents();
    }

    /**
     * Creates a new DViewPublicKeyFingerprint dialog.
     *
     * @param parent         The parent dialog
     * @param publicKey      Public key to fingerprint
     * @param fingerprintAlg Fingerprint algorithm
     */
    public DViewPublicKeyFingerprint(JDialog parent, PublicKey publicKey, PublicKeyFingerprintAlgorithm fingerprintAlg) {
        super(parent, ModalityType.DOCUMENT_MODAL);
        this.publicKey = publicKey;
        this.fingerprintAlg = fingerprintAlg;
        initComponents();
    }

    private void initComponents() {
        jbCopy = new JButton(res.getString("DViewPublicKeyFingerprint.jbCopy.text"));
        PlatformUtil.setMnemonic(jbCopy, res.getString("DViewPublicKeyFingerprint.jbCopy.mnemonic").charAt(0));
        jbCopy.setToolTipText(res.getString("DViewPublicKeyFingerprint.jbCopy.tooltip"));
        jbCopy.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewPublicKeyFingerprint.this);
                copyPressed();
            } finally {
                CursorUtil.setCursorFree(DViewPublicKeyFingerprint.this);
            }
        });

        jbOK = new JButton(res.getString("DViewPublicKeyFingerprint.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, jbCopy);

        jpFingerprint = new JPanel(new BorderLayout());
        jpFingerprint.setBorder(new EmptyBorder(5, 5, 5, 5));

        jtaFingerprint = new JTextArea();
        jtaFingerprint.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaFingerprint.setEditable(false);
        jtaFingerprint.setTabSize(4);
        jtaFingerprint.setLineWrap(true);
        // JGoodies - keep uneditable color same as editable
        jtaFingerprint.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);
        jtaFingerprint.setToolTipText(
                MessageFormat.format(res.getString("DViewPublicKeyFingerprint.jtaFingerprint.tooltip"),
                                     fingerprintAlg.friendly()));

        jspPolicy = PlatformUtil.createScrollPane(jtaFingerprint, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                                  ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jspPolicy.setPreferredSize(new Dimension(280, 125));
        jpFingerprint.add(jspPolicy, BorderLayout.CENTER);

        getContentPane().add(jpFingerprint, BorderLayout.CENTER);

        getContentPane().add(jpButtons, BorderLayout.SOUTH);

        setTitle(MessageFormat.format(res.getString("DViewPublicKeyFingerprint.Title"), fingerprintAlg.friendly()));
        setResizable(true);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());

        populateFingerprint();
    }

    private void populateFingerprint() {
        if (publicKey != null) {
            try {
                byte[] fingerprintBytes = PublicKeyFingerprintUtil.calculateFingerprint(publicKey, fingerprintAlg);
                String fingerprintHex = HexUtil.getHexString(fingerprintBytes, "", 0, 0);
                jtaFingerprint.setText(fingerprintHex);
            } catch (CryptoException ex) {
                DError.displayError(this.getParent(), ex);
                return;
            }
        } else {
            jtaFingerprint.setText("");
        }

        jtaFingerprint.setCaretPosition(0);
    }

    private void copyPressed() {
        String fingerprint = jtaFingerprint.getText();

        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        StringSelection copy = new StringSelection(fingerprint);
        clipboard.setContents(copy, copy);
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

        KeyPair caKeyPair = keyGen.genKeyPair();
        X509CertificateGenerator certGen = new X509CertificateGenerator(X509CertificateVersion.VERSION3);
        X509Certificate caCert = certGen.generateSelfSigned(new X500Name("cn=CA"), Date.from(Instant.now()),
                                                            Date.from(Instant.now().plus(3650, ChronoUnit.DAYS)),
                                                            caKeyPair.getPublic(), caKeyPair.getPrivate(),
                                                            SignatureType.SHA224WITHRSAANDMGF1, BigInteger.ONE);

        DViewPublicKeyFingerprint dialog = new DViewPublicKeyFingerprint(new JFrame(), caCert.getPublicKey(),
                                                                         PublicKeyFingerprintAlgorithm.SKI_METHOD1);
        DialogViewer.run(dialog);
    }
}
