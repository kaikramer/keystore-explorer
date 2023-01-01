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

package org.kse.gui.crypto.distributionpoints;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.generalname.JGeneralNames;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

public class DDistributionPointsChooser extends JEscDialog {

    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/distributionpoints/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JPanel jpButtons;
    private JButton jbOK;
    private JButton jbCancel;
    private JLabel jlDistributionPointFullName;
    private JGeneralNames jgnDistributionPointFullName;
    private JLabel jlDistributionPointReasonFlags;
    private JLabel jlDistributionPointCrlIssuer;
    private JGeneralNames jgnDistributionPointCrlIssuer;
    private JCheckBox jcbKeyCompromise;
    private JCheckBox jcbCACompromise;
    private JCheckBox jcbAffiliationChanged;
    private JCheckBox jcbSuperseded;
    private JCheckBox jcbCessationOfOperation;
    private JCheckBox jcbCertificateHold;
    private JCheckBox jcbPrivilegeWithdrawn;
    private JCheckBox jcbAACompromise;

    private DistributionPoint distributionPoint = null;

    public DDistributionPointsChooser(JFrame parent, String title, DistributionPoint distributionPoint) {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        initComponents(distributionPoint);
    }

    public DDistributionPointsChooser(JDialog parent, String title, DistributionPoint distributionPoint) {
        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        initComponents(distributionPoint);
    }

    private void initComponents(DistributionPoint distributionPoint) {

        jlDistributionPointFullName = new JLabel(
                res.getString("DDistributionPointsChooser.jlDistributionPointFullName.text"));

        jgnDistributionPointFullName = new JGeneralNames(
                res.getString("DDistributionPointsChooser.DistributionPointFullName.Title"));
        jgnDistributionPointFullName.setPreferredSize(new Dimension(550, 150));

        jlDistributionPointReasonFlags = new JLabel(
                res.getString("DDistributionPointsChooser.jlDistributionPointReasonFlags.text"));

        jcbKeyCompromise = new JCheckBox(res.getString("DDistributionPointsChooser.jcbKeyCompromise.text"));
        jcbKeyCompromise.setToolTipText(res.getString("DDistributionPointsChooser.jcbKeyCompromise.tooltip"));

        jcbCACompromise = new JCheckBox(res.getString("DDistributionPointsChooser.jcbCACompromise.text"));
        jcbCACompromise.setToolTipText(res.getString("DDistributionPointsChooser.jcbCACompromise.tooltip"));

        jcbAffiliationChanged = new JCheckBox(res.getString("DDistributionPointsChooser.jcbAffiliationChanged.text"));
        jcbAffiliationChanged.setToolTipText(res.getString("DDistributionPointsChooser.jcbAffiliationChanged.tooltip"));

        jcbSuperseded = new JCheckBox(res.getString("DDistributionPointsChooser.jcbSuperseded.text"));
        jcbSuperseded.setToolTipText(res.getString("DDistributionPointsChooser.jcbSuperseded.tooltip"));

        jcbCessationOfOperation = new JCheckBox(
                res.getString("DDistributionPointsChooser.jcbCessationOfOperation.text"));
        jcbCessationOfOperation.setToolTipText(
                res.getString("DDistributionPointsChooser.jcbCessationOfOperation.tooltip"));

        jcbCertificateHold = new JCheckBox(res.getString("DDistributionPointsChooser.jcbCertificateHold.text"));
        jcbCertificateHold.setToolTipText(res.getString("DDistributionPointsChooser.jcbCertificateHold.tooltip"));

        jcbPrivilegeWithdrawn = new JCheckBox(res.getString("DDistributionPointsChooser.jcbPrivilegeWithdrawn.text"));
        jcbPrivilegeWithdrawn.setToolTipText(res.getString("DDistributionPointsChooser.jcbPrivilegeWithdrawn.tooltip"));

        jcbAACompromise = new JCheckBox(res.getString("DDistributionPointsChooser.jcbAACompromise.text"));
        jcbAACompromise.setToolTipText(res.getString("DDistributionPointsChooser.jcbAACompromise.tooltip"));

        jlDistributionPointCrlIssuer = new JLabel(
                res.getString("DDistributionPointsChooser.jlDistributionPointCrlIssuer.text"));

        jgnDistributionPointCrlIssuer = new JGeneralNames(
                res.getString("DDistributionPointsChooser.DistributionPointCrlIssuer.Title"));
        jgnDistributionPointCrlIssuer.setPreferredSize(new Dimension(550, 150));

        jbOK = new JButton(res.getString("DGeneralNameChooser.jbOK.text"));
        jbCancel = new JButton(res.getString("DGeneralNameChooser.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[][][]", "[][]"));
        pane.add(jlDistributionPointFullName, "top");
        pane.add(jgnDistributionPointFullName, "span 3, wrap unrel");
        pane.add(jlDistributionPointReasonFlags, "");
        pane.add(jcbKeyCompromise, "");
        pane.add(jcbCACompromise, "");
        pane.add(jcbAffiliationChanged, "wrap");
        pane.add(jcbSuperseded, "skip");
        pane.add(jcbCessationOfOperation, "");
        pane.add(jcbCertificateHold, "wrap");
        pane.add(jcbPrivilegeWithdrawn, "skip");
        pane.add(jcbAACompromise, "wrap unrel");
        pane.add(jlDistributionPointCrlIssuer, "top");
        pane.add(jgnDistributionPointCrlIssuer, "span 3, wrap unrel");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jpButtons, "spanx, tag ok");

        jbOK.addActionListener(evt -> okPressed());
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        populate(distributionPoint);

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void populate(DistributionPoint distributionPoint) {
        if (distributionPoint != null) {
            DistributionPointName dist = distributionPoint.getDistributionPoint();
            if (dist != null) {
                GeneralNames generalNames = GeneralNames.getInstance(dist.getName());
                jgnDistributionPointFullName.setGeneralNames(generalNames);
            }
            GeneralNames cRLIssuer = distributionPoint.getCRLIssuer();
            if (cRLIssuer != null) {
                jgnDistributionPointCrlIssuer.setGeneralNames(cRLIssuer);
            }

            ReasonFlags reasonFlags = distributionPoint.getReasons();
            if (reasonFlags != null) {

                DERBitString reasonFlagsBitString = (DERBitString) reasonFlags.toASN1Primitive();
                int reasonFlagsInt = reasonFlagsBitString.intValue();

                if (hasReasonFlag(reasonFlagsInt, ReasonFlags.keyCompromise)) {
                    jcbKeyCompromise.setSelected(true);
                }
                if (hasReasonFlag(reasonFlagsInt, ReasonFlags.cACompromise)) {
                    jcbCACompromise.setSelected(true);
                }
                if (hasReasonFlag(reasonFlagsInt, ReasonFlags.affiliationChanged)) {
                    jcbAffiliationChanged.setSelected(true);
                }
                if (hasReasonFlag(reasonFlagsInt, ReasonFlags.superseded)) {
                    jcbSuperseded.setSelected(true);
                }
                if (hasReasonFlag(reasonFlagsInt, ReasonFlags.cessationOfOperation)) {
                    jcbCessationOfOperation.setSelected(true);
                }
                if (hasReasonFlag(reasonFlagsInt, ReasonFlags.certificateHold)) {
                    jcbCertificateHold.setSelected(true);
                }
                if (hasReasonFlag(reasonFlagsInt, ReasonFlags.privilegeWithdrawn)) {
                    jcbPrivilegeWithdrawn.setSelected(true);
                }
                if (hasReasonFlag(reasonFlagsInt, ReasonFlags.aACompromise)) {
                    jcbAACompromise.setSelected(true);
                }
            }
        }
    }

    private void okPressed() {

        DistributionPointName distributionPointName;

        ReasonFlags reasonFlags = null;
        int reasons = 0;

        if (jcbKeyCompromise.isSelected()) {
            reasons |= ReasonFlags.keyCompromise;
        }
        if (jcbCACompromise.isSelected()) {
            reasons |= ReasonFlags.cACompromise;
        }
        if (jcbAffiliationChanged.isSelected()) {
            reasons |= ReasonFlags.affiliationChanged;
        }
        if (jcbSuperseded.isSelected()) {
            reasons |= ReasonFlags.superseded;
        }
        if (jcbCessationOfOperation.isSelected()) {
            reasons |= ReasonFlags.cessationOfOperation;
        }
        if (jcbCertificateHold.isSelected()) {
            reasons |= ReasonFlags.certificateHold;
        }
        if (jcbPrivilegeWithdrawn.isSelected()) {
            reasons |= ReasonFlags.privilegeWithdrawn;
        }
        if (jcbAACompromise.isSelected()) {
            reasons |= ReasonFlags.aACompromise;
        }
        if (reasons > 0) {
            reasonFlags = new ReasonFlags(reasons);
        }

        if (jgnDistributionPointFullName.getGeneralNames().getNames().length == 0) {
            JOptionPane.showMessageDialog(this, res.getString(
                                                  "DDistributionPointsChooser.DistributionPointFullNameNumberNonZero.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        } else {
            distributionPointName = new DistributionPointName(jgnDistributionPointFullName.getGeneralNames());
        }

        GeneralNames cRLIssuer = null;
        if (jgnDistributionPointCrlIssuer.getGeneralNames().getNames().length > 0) {
            cRLIssuer = jgnDistributionPointCrlIssuer.getGeneralNames();
        }
        distributionPoint = new DistributionPoint(distributionPointName, reasonFlags, cRLIssuer);
        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    public DistributionPoint getDistributionPoint() {
        return distributionPoint;
    }

    private static boolean hasReasonFlag(int reasonFlags, int reasonFlag) {
        return (reasonFlags & reasonFlag) == reasonFlag;
    }

    public static void main(String[] args) throws Exception {
        DialogViewer.run(new DDistributionPointsChooser(new JFrame(), "DistributionPointsChooser", null));
    }

}
