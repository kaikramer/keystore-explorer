/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.HeadlessException;
import java.awt.event.KeyEvent;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.ResourceBundle;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;

import org.kse.crypto.x509.X500NameUtils;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.datetime.JDateTime;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that specifies the reason that a certificate is revoked
 */
public class DCrlReason extends JEscDialog {

    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");
    private static ResourceBundle resCryptoX509 = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlSubject;
    private JDistinguishedName jdnSubject;
    private JLabel jlRevocationDate;
    private JDateTime jdtRevocationDate;
    private JLabel jlReason;
    private JRadioButton jrbUnspecified;
    private JRadioButton jrbKeyCompromise;
    private JRadioButton jrbCACompromise;
    private JRadioButton jrbAffiliationChanged;
    private JRadioButton jrbSuperseded;
    private JRadioButton jrbCessationOfOperation;
    private JRadioButton jrbCertificateHold;
    private JRadioButton jrbRemoveFromCR;
    private JRadioButton jrbPrivilegeWithdrawn;
    private JRadioButton jrbAACompromise;

    private JButton jbOK;
    private JButton jbCancel;

    private CRLReason reason;
    private boolean ok = false;
    private Date revocationDate;
    private X509Certificate cert;

    /**
     * Creates a new DCrlReason
     *
     * @param parent The parent frame
     * @param cert   Certificate to revoke
     */
    public DCrlReason(JFrame parent, X509Certificate cert) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        setTitle(res.getString("DCrlReason.Title"));
        this.cert = cert;
        initComponents();
    }

    private void initComponents() {
        Date now = new Date();

        jlSubject = new JLabel(res.getString("DCrlReason.jlSubject.text"));
        jdnSubject = new JDistinguishedName(res.getString("DCrlReason.Subject.Title"), 40, false);

        jlRevocationDate = new JLabel(res.getString("DCrlReason.jlRevocationDate.text"));
        jdtRevocationDate = new JDateTime(res.getString("DCrlReason.jdtRevocationDate.text"), false);
        jdtRevocationDate.setDateTime(now);
        jdtRevocationDate.setToolTipText(res.getString("DCrlReason.jdtRevocationDate.tooltip"));

        jlReason = new JLabel(res.getString("DCrlReason.jlReason.text"));

        jrbUnspecified = new JRadioButton(getCrlReasonText(CRLReason.UNSPECIFIED));
        jrbUnspecified.setToolTipText(getCrlReasonTooltip(CRLReason.UNSPECIFIED));

        jrbKeyCompromise = new JRadioButton(getCrlReasonText(CRLReason.KEY_COMPROMISE));
        jrbKeyCompromise.setToolTipText(getCrlReasonTooltip(CRLReason.KEY_COMPROMISE));

        jrbCACompromise = new JRadioButton(getCrlReasonText(CRLReason.CA_COMPROMISE));
        jrbCACompromise.setToolTipText(getCrlReasonTooltip(CRLReason.CA_COMPROMISE));

        jrbAffiliationChanged = new JRadioButton(getCrlReasonText(CRLReason.AFFILIATION_CHANGED));
        jrbAffiliationChanged.setToolTipText(getCrlReasonTooltip(CRLReason.AFFILIATION_CHANGED));

        jrbSuperseded = new JRadioButton(getCrlReasonText(CRLReason.SUPERSEDED));
        jrbSuperseded.setToolTipText(getCrlReasonTooltip(CRLReason.SUPERSEDED));

        jrbCessationOfOperation = new JRadioButton(getCrlReasonText(CRLReason.CESSATION_OF_OPERATION));
        jrbCessationOfOperation.setToolTipText(getCrlReasonTooltip(CRLReason.CESSATION_OF_OPERATION));

        jrbCertificateHold = new JRadioButton(getCrlReasonText(CRLReason.CERTIFICATE_HOLD));
        jrbCertificateHold.setToolTipText(getCrlReasonTooltip(CRLReason.CERTIFICATE_HOLD));

        jrbRemoveFromCR = new JRadioButton(getCrlReasonText(CRLReason.REMOVE_FROM_CRL));
        jrbRemoveFromCR.setToolTipText(getCrlReasonTooltip(CRLReason.REMOVE_FROM_CRL));

        jrbPrivilegeWithdrawn = new JRadioButton(getCrlReasonText(CRLReason.PRIVILEGE_WITHDRAWN));
        jrbPrivilegeWithdrawn.setToolTipText(getCrlReasonTooltip(CRLReason.PRIVILEGE_WITHDRAWN));

        jrbAACompromise = new JRadioButton(getCrlReasonText(CRLReason.AA_COMPROMISE));
        jrbAACompromise.setToolTipText(getCrlReasonTooltip(CRLReason.AA_COMPROMISE));

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(jrbUnspecified);
        buttonGroup.add(jrbKeyCompromise);
        buttonGroup.add(jrbCACompromise);
        buttonGroup.add(jrbAffiliationChanged);
        buttonGroup.add(jrbSuperseded);
        buttonGroup.add(jrbCessationOfOperation);
        buttonGroup.add(jrbCertificateHold);
        buttonGroup.add(jrbRemoveFromCR);
        buttonGroup.add(jrbPrivilegeWithdrawn);
        buttonGroup.add(jrbAACompromise);

        jrbUnspecified.setSelected(true);

        jbOK = new JButton(res.getString("DCrlReason.jbOK.text"));
        jbCancel = new JButton(res.getString("DCrlReason.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[][][]", "[]"));
        pane.add(jlSubject, "");
        pane.add(jdnSubject, "spanx, wrap unrel");
        pane.add(jlRevocationDate, "");
        pane.add(jdtRevocationDate, "spanx, wrap unrel");
        pane.add(jlReason, "top");
        pane.add(jrbUnspecified, "left");
        pane.add(jrbKeyCompromise);
        pane.add(jrbCACompromise, "wrap");
        pane.add(jrbAffiliationChanged, "skip, left");
        pane.add(jrbSuperseded);
        pane.add(jrbCessationOfOperation, "wrap");
        pane.add(jrbCertificateHold, "skip, left");
        pane.add(jrbRemoveFromCR);
        pane.add(jrbPrivilegeWithdrawn, "wrap");
        pane.add(jrbAACompromise, "skip, left, wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jpButtons, "right, spanx");

        jbOK.addActionListener(evt -> okPressed());
        jbCancel.addActionListener(evt -> cancelPressed());

        populate();

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private String getCrlReasonText(CRLReason reason) {
        return resCryptoX509.getString("CrlReason." + reason.ordinal() + ".text");
    }

    private String getCrlReasonTooltip(CRLReason reason) {
        return resCryptoX509.getString("CrlReason." + reason.ordinal() + ".tooltip");
    }

    private void populate() {
        if (cert != null) {
            jdnSubject.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert.getSubjectX500Principal()));
        }
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    private void okPressed() {
        if (jrbUnspecified.isSelected()) {
            reason = CRLReason.UNSPECIFIED;
        } else if (jrbKeyCompromise.isSelected()) {
            reason = CRLReason.KEY_COMPROMISE;
        } else if (jrbCACompromise.isSelected()) {
            reason = CRLReason.CA_COMPROMISE;
        } else if (jrbAffiliationChanged.isSelected()) {
            reason = CRLReason.AFFILIATION_CHANGED;
        } else if (jrbSuperseded.isSelected()) {
            reason = CRLReason.SUPERSEDED;
        } else if (jrbCessationOfOperation.isSelected()) {
            reason = CRLReason.CESSATION_OF_OPERATION;
        } else if (jrbCertificateHold.isSelected()) {
            reason = CRLReason.CERTIFICATE_HOLD;
        } else if (jrbRemoveFromCR.isSelected()) {
            reason = CRLReason.REMOVE_FROM_CRL;
        } else if (jrbPrivilegeWithdrawn.isSelected()) {
            reason = CRLReason.PRIVILEGE_WITHDRAWN;
        } else if (jrbAACompromise.isSelected()) {
            reason = CRLReason.AA_COMPROMISE;
        }
        revocationDate = jdtRevocationDate.getDateTime();
        ok = true;
        closeDialog();
    }

    public CRLReason getReason() {
        return reason;
    }

    public Date getRevocationDate() {
        return revocationDate;
    }

    public boolean isOk() {
        return ok;
    }

    public static void main(String[] args) throws HeadlessException, UnsupportedLookAndFeelException {
        DialogViewer.run(new DCrlReason(new JFrame(), null));
    }
}
