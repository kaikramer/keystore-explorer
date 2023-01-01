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

import java.awt.Container;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.error.DError;

import net.miginfocom.swing.MigLayout;

/**
 * Component to view a fingerprint.
 */
public class JCertificateFingerprint extends JPanel {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

    private JComboBox<DigestType> jcbFingerprintAlg;
    private JTextField jtfCertificateFingerprint;
    private JButton jbViewCertificateFingerprint;

    private byte[] encodedCertificate;

    /**
     * Construct a JCertificateFingerprint.
     *
     * @param columns Size of text field
     */
    public JCertificateFingerprint(int columns) {
        initComponents(columns);
    }

    private void initComponents(int columns) {
        jcbFingerprintAlg = new JComboBox<>();
        jcbFingerprintAlg.setToolTipText(res.getString("JCertificateFingerprint.jcbFingerprintAlg.tooltip"));
        jcbFingerprintAlg.setMaximumRowCount(10);
        jcbFingerprintAlg.addItemListener(evt -> populateFingerprint());

        jtfCertificateFingerprint = new JTextField(columns);
        jtfCertificateFingerprint.setEditable(false);
        jtfCertificateFingerprint.setToolTipText(
                res.getString("JCertificateFingerprint.jtfCertificateFingerprint.tooltip"));

        ImageIcon viewIcon = new ImageIcon(getClass().getResource("images/view_cert_fingerprint.png"));
        jbViewCertificateFingerprint = new JButton(viewIcon);

        jbViewCertificateFingerprint.setToolTipText(
                res.getString("JCertificateFingerprint.jbViewCertificateFingerprint.tooltip"));
        jbViewCertificateFingerprint.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JCertificateFingerprint.this);
                displayFingerprint();
            } finally {
                CursorUtil.setCursorFree(JCertificateFingerprint.this);
            }
        });

        this.setLayout(new MigLayout("insets 0, fill", "[]", "[]"));
        this.add(jcbFingerprintAlg, "");
        this.add(jtfCertificateFingerprint, "");
        this.add(jbViewCertificateFingerprint, "");

        populateFingerprintAlgs();
        populateFingerprint();
    }

    private void populateFingerprintAlgs() {
        DigestType[] digestAlgs = DigestType.values();

        for (DigestType digestAlg : digestAlgs) {
            jcbFingerprintAlg.addItem(digestAlg);
        }

        jcbFingerprintAlg.setSelectedIndex(0);
    }

    /**
     * Set encoded certificate.
     *
     * @param encodedCertificate Encoded certificate
     */
    public void setEncodedCertificate(byte[] encodedCertificate) {
        this.encodedCertificate = encodedCertificate;
        populateFingerprint();
    }

    public void setFingerprintAlg(DigestType fingerprintAlg) {
        jcbFingerprintAlg.setSelectedItem(fingerprintAlg);
    }

    public DigestType getSelectedFingerprintAlg() {
        return (DigestType) jcbFingerprintAlg.getSelectedItem();
    }

    /**
     * Sets whether or not the component is enabled.
     *
     * @param enabled True if this component should be enabled, false otherwise
     */
    @Override
    public void setEnabled(boolean enabled) {
        jbViewCertificateFingerprint.setEnabled(enabled);
    }

    private void populateFingerprint() {
        if (encodedCertificate != null) {
            DigestType fingerprintAlg = (DigestType) jcbFingerprintAlg.getSelectedItem();

            try {
                jtfCertificateFingerprint.setText(
                        DigestUtil.getFriendlyMessageDigest(encodedCertificate, fingerprintAlg));
            } catch (CryptoException ex) {
                DError.displayError(getTopLevelAncestor(), ex);
                return;
            }
        } else {
            jtfCertificateFingerprint.setText("");
        }

        jtfCertificateFingerprint.setCaretPosition(0);
    }

    private void displayFingerprint() {
        Container container = getTopLevelAncestor();

        DigestType fingerprintAlg = (DigestType) jcbFingerprintAlg.getSelectedItem();

        if (container instanceof JDialog) {
            DViewCertificateFingerprint dViewCertificateFingerprint = new DViewCertificateFingerprint(
                    (JDialog) container, encodedCertificate, fingerprintAlg);
            dViewCertificateFingerprint.setLocationRelativeTo(container);
            dViewCertificateFingerprint.setVisible(true);
        } else if (container instanceof JFrame) {
            DViewCertificateFingerprint dViewCertificateFingerprint = new DViewCertificateFingerprint(
                    (JFrame) container, encodedCertificate, fingerprintAlg);
            dViewCertificateFingerprint.setLocationRelativeTo(container);
            dViewCertificateFingerprint.setVisible(true);
        }
    }
}
