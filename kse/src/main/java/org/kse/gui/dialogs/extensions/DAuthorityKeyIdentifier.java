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
package org.kse.gui.dialogs.extensions;

import java.awt.Container;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.crypto.JKeyIdentifier;
import org.kse.gui.crypto.generalname.JGeneralNames;
import org.kse.gui.error.DError;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to add or edit an Authority Key Identifier extension.
 */
public class DAuthorityKeyIdentifier extends DExtension {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlKeyIdentifier;
    private JKeyIdentifier jkiKeyIdentifier;
    private JLabel jlAuthorityCertIssuer;
    private JGeneralNames jgnAuthorityCertIssuer;
    private JLabel jlAuthorityCertSerialNumber;
    private JTextField jtfAuthorityCertSerialNumber;
    private JButton jbOK;
    private JButton jbCancel;

    private byte[] value;
    private PublicKey authorityPublicKey;
    private SubjectKeyIdentifier authoritySubjectKeyIdentifier;

    /**
     * Creates a new DAuthorityKeyIdentifier dialog.
     *
     * @param parent                    The parent dialog
     * @param authorityPublicKey        Authority public key
     * @param authorityCertName         Authority certificate name
     * @param authorityCertSerialNumber Authority certificate serial number
     * @param authoritySki              Authority subject key identifier extension
     */
    public DAuthorityKeyIdentifier(JDialog parent, PublicKey authorityPublicKey, X500Name authorityCertName,
                                   BigInteger authorityCertSerialNumber, SubjectKeyIdentifier authoritySki) {
        super(parent);

        setTitle(res.getString("DAuthorityKeyIdentifier.Title"));
        this.authorityPublicKey = authorityPublicKey;
        this.authoritySubjectKeyIdentifier = authoritySki;
        initComponents();
        prepopulateWithAuthorityCertDetails(authorityCertName, authorityCertSerialNumber);
    }

    /**
     * Creates a new DAuthorityKeyIdentifier dialog.
     *
     * @param parent             The parent dialog
     * @param value              Authority Key Identifier DER-encoded
     * @param authorityPublicKey Authority public key
     * @param authoritySki       Authority subject key identifier extension
     */
    public DAuthorityKeyIdentifier(JDialog parent, byte[] value, PublicKey authorityPublicKey,
            SubjectKeyIdentifier authoritySki) {
        super(parent);
        setTitle(res.getString("DAuthorityKeyIdentifier.Title"));
        this.authorityPublicKey = authorityPublicKey;
        this.authoritySubjectKeyIdentifier = authoritySki;
        initComponents();
        prepopulateWithValue(value);
    }

    private void initComponents() {
        jlKeyIdentifier = new JLabel(res.getString("DAuthorityKeyIdentifier.jlKeyIdentifer.text"));

        jkiKeyIdentifier = new JKeyIdentifier(res.getString("DAuthorityKeyIdentifier.KeyIdentifier.Title"),
                                              authorityPublicKey);

        jlAuthorityCertIssuer = new JLabel(res.getString("DAuthorityKeyIdentifier.jlAuthorityCertIssuer.text"));

        jgnAuthorityCertIssuer = new JGeneralNames(res.getString("DAuthorityKeyIdentifier.AuthorityCertIssuer.Title"));
        jgnAuthorityCertIssuer.setPreferredSize(new Dimension(400, 150));

        jlAuthorityCertSerialNumber = new JLabel(
                res.getString("DAuthorityKeyIdentifier.jlAuthorityCertSerialNumber.text"));

        jtfAuthorityCertSerialNumber = new JTextField(20);

        jbOK = new JButton(res.getString("DAuthorityKeyIdentifier.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DAuthorityKeyIdentifier.jbCancel.text"));
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
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]"));
        pane.add(jlKeyIdentifier);
        pane.add(jkiKeyIdentifier, "wrap");
        pane.add(jlAuthorityCertIssuer, "top");
        pane.add(jgnAuthorityCertIssuer, "wrap");
        pane.add(jlAuthorityCertSerialNumber);
        pane.add(jtfAuthorityCertSerialNumber, "wrap");
        pane.add(new JSeparator(), "spanx, growx");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                cancelPressed();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void prepopulateWithAuthorityCertDetails(X500Name authorityCertName, BigInteger authorityCertSerialNumber) {
        if (authoritySubjectKeyIdentifier != null) {
            jkiKeyIdentifier.setKeyIdentifier(authoritySubjectKeyIdentifier.getKeyIdentifier());
        }

        if (authorityCertName != null) {
            try {
                GeneralName generalName = new GeneralName(GeneralName.directoryName, authorityCertName);
                GeneralNames generalNames = new GeneralNames(generalName);

                jgnAuthorityCertIssuer.setGeneralNames(generalNames);
            } catch (Exception e) {
                DError.displayError(this, e);
                return;
            }
        }

        if (authorityCertSerialNumber != null) {
            jtfAuthorityCertSerialNumber.setText("" + authorityCertSerialNumber);
            jtfAuthorityCertSerialNumber.setCaretPosition(0);
        }
    }

    private void prepopulateWithValue(byte[] value) {
        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(value);

        if (authorityKeyIdentifier.getKeyIdentifierOctets() != null) {
            jkiKeyIdentifier.setKeyIdentifier(authorityKeyIdentifier.getKeyIdentifierOctets());
        }

        GeneralNames authorityCertIssuer = authorityKeyIdentifier.getAuthorityCertIssuer();

        if (authorityCertIssuer != null) {
            jgnAuthorityCertIssuer.setGeneralNames(authorityCertIssuer);
        }

        BigInteger authorityCertSerialNumber = authorityKeyIdentifier.getAuthorityCertSerialNumber();

        if (authorityCertSerialNumber != null) {
            jtfAuthorityCertSerialNumber.setText("" + authorityCertSerialNumber);
            jtfAuthorityCertSerialNumber.setCaretPosition(0);
        }
    }

    private void okPressed() {
        byte[] keyIdentifier = jkiKeyIdentifier.getKeyIdentifier();
        GeneralNames authorityCertIssuer = jgnAuthorityCertIssuer.getGeneralNames();
        BigInteger authorityCertSerialNumber = null;

        String authorityCertSerialNumberStr = jtfAuthorityCertSerialNumber.getText().trim();

        if (!authorityCertSerialNumberStr.isEmpty()) {
            try {
                authorityCertSerialNumber = new BigInteger(authorityCertSerialNumberStr);
                if (authorityCertSerialNumber.compareTo(BigInteger.ONE) < 0) {
                    JOptionPane.showMessageDialog(this, res.getString(
                                                          "DAuthorityKeyIdentifier.AuthorityCertSerialNumberNonZero" +
                                                          ".message"), getTitle(),
                                                  JOptionPane.WARNING_MESSAGE);
                    return;
                }
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, res.getString(
                                                      "DAuthorityKeyIdentifier.AuthorityCertSerialNumberNotInteger" +
                                                      ".message"), getTitle(),
                                              JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        // Either key identifier or authority cert issuer and authority cert
        // serial number are required
        if ((keyIdentifier == null) &&
            ((authorityCertIssuer.getNames().length == 0) || (authorityCertSerialNumber == null))) {
            JOptionPane.showMessageDialog(this, res.getString("DAuthorityKeyIdentifier.ValueReq.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        AuthorityKeyIdentifier authorityKeyIdentifier;

        if ((keyIdentifier != null) && (authorityCertSerialNumber == null)) {

            // only key identifier
            authorityKeyIdentifier = new AuthorityKeyIdentifier(keyIdentifier);

        } else if (keyIdentifier == null) {

            // only issuer / serial
            authorityKeyIdentifier = new AuthorityKeyIdentifier(authorityCertIssuer, authorityCertSerialNumber);
        } else {

            // both
            authorityKeyIdentifier = new AuthorityKeyIdentifier(keyIdentifier, authorityCertIssuer,
                                                                authorityCertSerialNumber);
        }

        try {
            value = authorityKeyIdentifier.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            DError.displayError(this, e);
            return;
        }

        closeDialog();
    }

    @Override
    public byte[] getValue() {
        return value;
    }

    @Override
    public String getOid() {
        return X509ExtensionType.AUTHORITY_KEY_IDENTIFIER.oid();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
