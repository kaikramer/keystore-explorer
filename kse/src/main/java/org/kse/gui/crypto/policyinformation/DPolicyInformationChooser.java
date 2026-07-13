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
package org.kse.gui.crypto.policyinformation;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.error.DError;
import org.kse.gui.oid.JObjectId;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to choose policy information.
 */
public class DPolicyInformationChooser extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/policyinformation/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlPolicyIdentifier;
    private JObjectId joiPolicyIdentifier;
    private JLabel jlPolicyQualifiers;
    private JPolicyQualifierInfo jpqPolicyQualifiers;
    private JPanel jpButtons;
    private JButton jbOK;
    private JButton jbCancel;

    private PolicyInformation policyInformation;

    /**
     * Constructs a new DPolicyInformationChooser dialog.
     *
     * @param parent            The parent frame
     * @param title             The dialog title
     * @param policyInformation Policy information
     * @throws IOException If policy information could not be decoded
     */
    public DPolicyInformationChooser(JFrame parent, String title, PolicyInformation policyInformation)
            throws IOException {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        initComponents(policyInformation);
    }

    /**
     * Constructs a new DPolicyInformationChooser dialog.
     *
     * @param parent            The parent dialog
     * @param title             The dialog title
     * @param policyInformation Policy information
     * @throws IOException If policy information could not be decoded
     */
    public DPolicyInformationChooser(JDialog parent, String title, PolicyInformation policyInformation)
            throws IOException {
        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        initComponents(policyInformation);
    }

    private void initComponents(PolicyInformation policyInformation) throws IOException {
        jlPolicyIdentifier = new JLabel(res.getString("DPolicyInformationChooser.jlPolicyIdentifier.text"));

        joiPolicyIdentifier = new JObjectId(res.getString("DPolicyInformationChooser.PolicyIdentifier.Text"));
        joiPolicyIdentifier.setToolTipText(res.getString("DPolicyInformationChooser.joiPolicyIdentifier.tooltip"));

        jlPolicyQualifiers = new JLabel(res.getString("DPolicyInformationChooser.jlPolicyQualifiers.text"));

        jpqPolicyQualifiers = new JPolicyQualifierInfo(
                res.getString("DPolicyInformationChooser.PolicyQualifierInfo.Title"));
        jpqPolicyQualifiers.setPreferredSize(new Dimension(400, 150));

        jbOK = new JButton(res.getString("DPolicyInformationChooser.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DPolicyInformationChooser.jbCancel.text"));
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

        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[][]"));
        pane.add(jlPolicyIdentifier, "");
        pane.add(joiPolicyIdentifier, "wrap");
        pane.add(jlPolicyQualifiers, "top");
        pane.add(jpqPolicyQualifiers, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jpButtons, "spanx, growx");

        populate(policyInformation);

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void populate(PolicyInformation policyInformation) throws IOException {
        if (policyInformation != null) {
            joiPolicyIdentifier.setObjectId(policyInformation.getPolicyIdentifier());

            ASN1Sequence policyQualifierInfoSeq = policyInformation.getPolicyQualifiers();

            if (policyQualifierInfoSeq != null) {
                List<PolicyQualifierInfo> policyQualifierInfo = new ArrayList<>();

                for (int i = 0; i < policyQualifierInfoSeq.size(); i++) {
                    PolicyQualifierInfo policyQualInfo = PolicyQualifierInfo.getInstance(
                            policyQualifierInfoSeq.getObjectAt(i));
                    policyQualifierInfo.add(policyQualInfo);
                }

                jpqPolicyQualifiers.setPolicyQualifierInfo(policyQualifierInfo);
            }
        }
    }

    /**
     * Get selected policy information.
     *
     * @return Policy information, or null if none
     */
    public PolicyInformation getPolicyInformation() {
        return policyInformation;
    }

    private void okPressed() {
        ASN1ObjectIdentifier policyIdentifer = joiPolicyIdentifier.getObjectId();

        if (policyIdentifer == null) {
            JOptionPane.showMessageDialog(this,
                                          res.getString("DPolicyInformationChooser.PolicyIdentifierValueReq.message"),
                                          getTitle(), JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<PolicyQualifierInfo> policyQualifierInfo = jpqPolicyQualifiers.getPolicyQualifierInfo();

        if (!policyQualifierInfo.isEmpty()) {
            ASN1EncodableVector policyQualifiersVec = new ASN1EncodableVector();

            for (PolicyQualifierInfo policyQualInfo : policyQualifierInfo) {
                try {
                    policyQualifiersVec.add(policyQualInfo);
                } catch (Exception e) {
                    DError.displayError(this, e);
                    return;
                }
            }

            DERSequence policyQualifiersSeq = new DERSequence(policyQualifiersVec);
            policyInformation = new PolicyInformation(policyIdentifer, policyQualifiersSeq);
        } else {

            policyInformation = new PolicyInformation(policyIdentifer);
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
