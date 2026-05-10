/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;
import org.kse.crypto.publickey.KeyIdentifierGenerator;
import org.kse.gui.components.JEscDialog;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to choose a key identifier value.
 */
public class DKeyIdentifierChooser extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");
    private static ResourceBundle resCryptoDigest = ResourceBundle.getBundle("org/kse/crypto/digest/resources");


    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlGenerationMethod;
    private JRadioButton jrb160BitHash;
    private JRadioButton jrb64BitHash;
    private JRadioButton jrbSha1OverSpki;
    private JRadioButton jrbSha256OverSpki;
    private JButton jbOK;
    private JButton jbCancel;

    private PublicKey publicKey;
    private byte[] keyIdentifier160Bit;
    private byte[] keyIdentifier64Bit;
    private byte[] keyIdentifierSha1OverSpki;
    private byte[] keyIdentifierSha256OverSpki;
    private byte[] keyIdentifier;

    /**
     * Constructs a new DKeyIdentifierChooser dialog.
     *
     * @param parent        The parent frame
     * @param title         The dialog title
     * @param publicKey     Public key
     * @param keyIdentifier Key identifier
     * @throws CryptoException If there was a problem generating identifiers
     */
    public DKeyIdentifierChooser(JFrame parent, String title, PublicKey publicKey, byte[] keyIdentifier)
            throws CryptoException {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        this.publicKey = publicKey;
        initComponents(keyIdentifier);
    }

    /**
     * Constructs a new DKeyIdentifierChooser dialog.
     *
     * @param parent        The parent dialog
     * @param title         The dialog title
     * @param publicKey     Public key
     * @param keyIdentifier Key identifier
     * @throws CryptoException If there was a problem generating identifiers
     */
    public DKeyIdentifierChooser(JDialog parent, String title, PublicKey publicKey, byte[] keyIdentifier)
            throws CryptoException {
        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        this.publicKey = publicKey;
        initComponents(keyIdentifier);
    }

    private void initComponents(byte[] keyIdentifier) throws CryptoException {
        jlGenerationMethod = new JLabel(res.getString("DKeyIdentifierChooser.jlGenerationMethod.text"));

        jrb160BitHash = new JRadioButton(resCryptoDigest.getString("PublicKeyFingerprintAlgorithm.SkiMethod1.text"));
        jrb160BitHash.setToolTipText(resCryptoDigest.getString("PublicKeyFingerprintAlgorithm.SkiMethod1.tooltip"));

        jrb64BitHash = new JRadioButton(resCryptoDigest.getString("PublicKeyFingerprintAlgorithm.SkiMethod2.text"));
        jrb64BitHash.setToolTipText(resCryptoDigest.getString("PublicKeyFingerprintAlgorithm.SkiMethod2.tooltip"));

        jrbSha1OverSpki = new JRadioButton(resCryptoDigest.getString("PublicKeyFingerprintAlgorithm.Sha1overSpki.text"));
        jrbSha1OverSpki.setToolTipText(resCryptoDigest.getString("PublicKeyFingerprintAlgorithm.Sha1overSpki.tooltip"));

        jrbSha256OverSpki = new JRadioButton(resCryptoDigest.getString("PublicKeyFingerprintAlgorithm.Sha256overSpki.text"));
        jrbSha256OverSpki.setToolTipText(resCryptoDigest.getString("PublicKeyFingerprintAlgorithm.Sha256overSpki.tooltip"));

        ButtonGroup bgKeyIdentifier = new ButtonGroup();
        bgKeyIdentifier.add(jrb160BitHash);
        bgKeyIdentifier.add(jrb64BitHash);
        bgKeyIdentifier.add(jrbSha1OverSpki);
        bgKeyIdentifier.add(jrbSha256OverSpki);

        jbOK = new JButton(res.getString("DKeyIdentifierChooser.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DKeyIdentifierChooser.jbCancel.text"));
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        Container pane = getContentPane();
        setLayout(new MigLayout("insets dialog, fill", "[]", "[]"));
        pane.add(jlGenerationMethod, "wrap");
        pane.add(jrb160BitHash, "wrap");
        pane.add(jrb64BitHash, "wrap");
        pane.add(jrbSha1OverSpki, "wrap");
        pane.add(jrbSha256OverSpki, "wrap");
        pane.add(new JSeparator(), "spanx, growx");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

        populate(keyIdentifier);

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void populate(byte[] keyIdentifier) throws CryptoException {
        KeyIdentifierGenerator keyIdentifierGenerator = new KeyIdentifierGenerator(publicKey);

        // This strategy is similar to PublicKeyFingerprintUtil.calculateFingerprint
        keyIdentifier160Bit = keyIdentifierGenerator.generate160BitHashId();
        keyIdentifier64Bit = keyIdentifierGenerator.generate64BitHashId();
        keyIdentifierSha1OverSpki = DigestUtil.getMessageDigest(publicKey.getEncoded(), DigestType.SHA1);
        keyIdentifierSha256OverSpki = DigestUtil.getMessageDigest(publicKey.getEncoded(), DigestType.SHA256);

        if (keyIdentifier == null) {
            jrb160BitHash.setSelected(true);
        } else if (keyIdentifier.length == keyIdentifier160Bit.length) {
            if (Arrays.equals(keyIdentifier, keyIdentifier160Bit)) {
                jrb160BitHash.setSelected(true);
            } else {
                jrbSha1OverSpki.setSelected(true);
            }
        } else if (keyIdentifier.length == keyIdentifier64Bit.length) {
            jrb64BitHash.setSelected(true);
        } else {
            jrbSha256OverSpki.setSelected(true);
        }
    }

    /**
     * Get selected key identifier.
     *
     * @return Key identifier, or null if none
     */
    public byte[] getKeyIdentifier() {
        return keyIdentifier;
    }

    private void okPressed() {
        if (jrb160BitHash.isSelected()) {
            keyIdentifier = keyIdentifier160Bit;
        } else if (jrb64BitHash.isSelected()) {
            keyIdentifier = keyIdentifier64Bit;
        } else if (jrbSha1OverSpki.isSelected()) {
            keyIdentifier = keyIdentifierSha1OverSpki;
        } else {
            keyIdentifier = keyIdentifierSha256OverSpki;
        }

        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
