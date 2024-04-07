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
package org.kse.gui.crypto;

import java.awt.Container;
import java.security.PublicKey;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.kse.crypto.digest.PublicKeyFingerprintAlgorithm;
import org.kse.crypto.digest.PublicKeyFingerprintUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.io.HexUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Component to view a fingerprint.
 */
public class JPublicKeyFingerprint extends JPanel {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

    private JComboBox<PublicKeyFingerprintAlgorithm> jcbFingerprintAlg;
    private JTextField jtfPublicKeyFingerprint;
    private JButton jbViewPublicKeyFingerprint;

    private PublicKey publicKey;

    /**
     * Construct a JPublicKeyFingerprint.
     *
     * @param columns Size of text field
     */
    public JPublicKeyFingerprint(int columns) {
        initComponents(columns);
    }

    private void initComponents(int columns) {
        jcbFingerprintAlg = new JComboBox<>();
        jcbFingerprintAlg.setToolTipText(res.getString("JPublicKeyFingerprint.jcbFingerprintAlg.tooltip"));
        jcbFingerprintAlg.setMaximumRowCount(10);
        jcbFingerprintAlg.addItemListener(evt -> populateFingerprint());

        jtfPublicKeyFingerprint = new JTextField(columns);
        jtfPublicKeyFingerprint.setEditable(false);
        jtfPublicKeyFingerprint.setToolTipText(
                res.getString("JPublicKeyFingerprint.jtfPublicKeyFingerprint.tooltip"));

        ImageIcon viewIcon = new ImageIcon(getClass().getResource("images/view_cert_fingerprint.png"));
        jbViewPublicKeyFingerprint = new JButton(viewIcon);

        jbViewPublicKeyFingerprint.setToolTipText(
                res.getString("JPublicKeyFingerprint.jbViewPublicKeyFingerprint.tooltip"));
        jbViewPublicKeyFingerprint.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JPublicKeyFingerprint.this);
                displayFingerprint();
            } finally {
                CursorUtil.setCursorFree(JPublicKeyFingerprint.this);
            }
        });

        this.setLayout(new MigLayout("insets 0, fill", "[]", "[]"));
        this.add(jcbFingerprintAlg, "");
        this.add(jtfPublicKeyFingerprint, "");
        this.add(jbViewPublicKeyFingerprint, "");

        populateFingerprintAlgs();
        populateFingerprint();
    }

    private void populateFingerprintAlgs() {
        PublicKeyFingerprintAlgorithm[] fingerprintAlgorithms = PublicKeyFingerprintAlgorithm.values();

        for (PublicKeyFingerprintAlgorithm fingerprintAlgorithm : fingerprintAlgorithms) {
            jcbFingerprintAlg.addItem(fingerprintAlgorithm);
        }
    }

    /**
     * Set public key for fingerprint calculation.
     *
     * @param publicKey Public key
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        populateFingerprint();
    }

    public void setFingerprintAlg(PublicKeyFingerprintAlgorithm fingerprintAlg) {
        jcbFingerprintAlg.setSelectedItem(fingerprintAlg);
    }

    public PublicKeyFingerprintAlgorithm getSelectedFingerprintAlg() {
        return (PublicKeyFingerprintAlgorithm) jcbFingerprintAlg.getSelectedItem();
    }

    /**
     * Sets whether or not the component is enabled.
     *
     * @param enabled True if this component should be enabled, false otherwise
     */
    @Override
    public void setEnabled(boolean enabled) {
        jbViewPublicKeyFingerprint.setEnabled(enabled);
    }

    private void populateFingerprint() {
        if (publicKey != null) {
            PublicKeyFingerprintAlgorithm fingerprintAlg =
                    (PublicKeyFingerprintAlgorithm) jcbFingerprintAlg.getSelectedItem();

            try {
                byte[] fingerprint = PublicKeyFingerprintUtil.calculateFingerprint(publicKey, fingerprintAlg);
                String fingerprintHex = HexUtil.getHexStringWithSep(fingerprint, ':');
                jtfPublicKeyFingerprint.setText(fingerprintHex);
            } catch (Exception ex) {
                DError.displayError(getTopLevelAncestor(), ex);
                return;
            }
        } else {
            jtfPublicKeyFingerprint.setText("");
        }

        jtfPublicKeyFingerprint.setCaretPosition(0);
    }

    private void displayFingerprint() {
        Container container = getTopLevelAncestor();

        PublicKeyFingerprintAlgorithm fingerprintAlg =
                (PublicKeyFingerprintAlgorithm) jcbFingerprintAlg.getSelectedItem();

        if (container instanceof JDialog) {
            DViewPublicKeyFingerprint dViewPublicKeyFingerprint = new DViewPublicKeyFingerprint(
                    (JDialog) container, publicKey, fingerprintAlg);
            dViewPublicKeyFingerprint.setLocationRelativeTo(container);
            dViewPublicKeyFingerprint.setVisible(true);
        } else if (container instanceof JFrame) {
            DViewPublicKeyFingerprint dViewPublicKeyFingerprint = new DViewPublicKeyFingerprint(
                    (JFrame) container, publicKey, fingerprintAlg);
            dViewPublicKeyFingerprint.setLocationRelativeTo(container);
            dViewPublicKeyFingerprint.setVisible(true);
        }
    }
}
