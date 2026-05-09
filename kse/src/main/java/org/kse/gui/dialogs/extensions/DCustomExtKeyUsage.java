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
import java.util.HashSet;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.crypto.customextkeyusage.JCustomExtendedKeyUsage;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to add or edit custom extended key usages.
 */
public class DCustomExtKeyUsage extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlCustomExtendedKeyUsage;
    private JCustomExtendedKeyUsage jCustomExtendedKeyUsage;
    private JButton jbOK;
    private JButton jbCancel;

    private Set<ASN1ObjectIdentifier> customExtUsageOids;

    /**
     * Creates a new DCustomExtKeyUsage dialog.
     *
     * @param parent The parent dialog
     * @param customExtUsageOids Set of OIDs for pre-populating in the dialog.
     */
    public DCustomExtKeyUsage(JDialog parent, Set<ASN1ObjectIdentifier> customExtUsageOids) {
        super(parent, ModalityType.DOCUMENT_MODAL);
        setTitle(res.getString("DCustomExtendedKeyUsage.Title"));
        this.customExtUsageOids = customExtUsageOids;
        initComponents();
        prepopulateWithOidList(customExtUsageOids);
    }

    private void initComponents() {
        jlCustomExtendedKeyUsage = new JLabel(res.getString("DCustomExtendedKeyUsage.jlCustomExtendedKeyUsage.text"));

        jCustomExtendedKeyUsage = new JCustomExtendedKeyUsage(
                res.getString("DCustomExtendedKeyUsage.jCustomExtendedKeyUsage.text"));
        jCustomExtendedKeyUsage.setPreferredSize(new Dimension(400, 150));

        jbOK = new JButton(res.getString("DCustomExtendedKeyUsage.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DCustomExtendedKeyUsage.jbCancel.text"));
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
        pane.add(jlCustomExtendedKeyUsage, "wrap");
        pane.add(jCustomExtendedKeyUsage, "wrap");
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

    private void prepopulateWithOidList(Set<ASN1ObjectIdentifier> customExtKeyUsageOids) {
        Set<ASN1ObjectIdentifier> oids = new HashSet<>(customExtKeyUsageOids);
        jCustomExtendedKeyUsage.setCustomExtKeyUsages(oids);
    }

    private void okPressed() {
        Set<ASN1ObjectIdentifier> objectIds = jCustomExtendedKeyUsage.getCustomExtKeyUsages();
        if (objectIds.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DCustomExtendedKeyUsage.ValueReq.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }
        customExtUsageOids = objectIds;

        closeDialog();
    }

    /**
     * Get extension value DER-encoded.
     *
     * @return Extension value
     */
    public Set<ASN1ObjectIdentifier> getObjectIds() {
        return customExtUsageOids;
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
