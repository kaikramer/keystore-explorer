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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.crypto.policyinformation.JPolicyInformation;
import org.kse.gui.error.DError;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to add or edit a Certificate Policies extension.
 */
public class DCertificatePolicies extends DExtension {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlCertificatePolicies;
    private JPolicyInformation jpiCertificatePolicies;
    private JButton jbOK;
    private JButton jbCancel;

    private byte[] value;

    /**
     * Creates a new DCertificatePolicies dialog.
     *
     * @param parent The parent dialog
     */
    public DCertificatePolicies(JDialog parent) {
        super(parent);

        setTitle(res.getString("DCertificatePolicies.Title"));
        initComponents();
    }

    /**
     * Creates a new DCertificatePolicies dialog.
     *
     * @param parent The parent dialog
     * @param value  Certificate Policies DER-encoded
     * @throws IOException If value could not be decoded
     */
    public DCertificatePolicies(JDialog parent, byte[] value) throws IOException {
        super(parent);
        setTitle(res.getString("DCertificatePolicies.Title"));
        initComponents();
        prepopulateWithValue(value);
    }

    private void initComponents() {
        jlCertificatePolicies = new JLabel(res.getString("DCertificatePolicies.jlCertificatePolicies.text"));

        jpiCertificatePolicies = new JPolicyInformation(res.getString("DCertificatePolicies.PolicyInformation.Title"));
        jpiCertificatePolicies.setPreferredSize(new Dimension(400, 150));

        jbOK = new JButton(res.getString("DCertificatePolicies.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DCertificatePolicies.jbCancel.text"));
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
        pane.setLayout(new MigLayout("insets dialog, fill", "[]"));
        pane.add(jlCertificatePolicies, "wrap");
        pane.add(jpiCertificatePolicies, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
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

    private void prepopulateWithValue(byte[] value) throws IOException {
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);

        List<PolicyInformation> accessDescriptionList = new ArrayList<>(
                Arrays.asList(certificatePolicies.getPolicyInformation()));

        jpiCertificatePolicies.setPolicyInformation(accessDescriptionList);
    }

    private void okPressed() {
        List<PolicyInformation> policyInformation = jpiCertificatePolicies.getPolicyInformation();

        if (policyInformation.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DCertificatePolicies.ValueReq.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        CertificatePolicies certificatePolicies = new CertificatePolicies(
                policyInformation.toArray(PolicyInformation[]::new));

        try {
            value = certificatePolicies.getEncoded(ASN1Encoding.DER);
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
        return X509ExtensionType.CERTIFICATE_POLICIES.oid();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
