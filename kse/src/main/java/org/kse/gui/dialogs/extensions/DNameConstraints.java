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
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.kse.crypto.x509.GeneralSubtrees;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.crypto.generalsubtree.JGeneralSubtrees;
import org.kse.gui.error.DError;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to add or edit a Name Constraints extension.
 */
public class DNameConstraints extends DExtension {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlPermittedSubtrees;
    private JGeneralSubtrees jgsPermittedSubtrees;
    private JLabel jlExcludedSubtrees;
    private JGeneralSubtrees jgsExcludedSubtrees;
    private JButton jbOK;
    private JButton jbCancel;

    private byte[] value;

    /**
     * Creates a new DNameConstraints dialog.
     *
     * @param parent The parent dialog
     */
    public DNameConstraints(JDialog parent) {
        super(parent);
        setTitle(res.getString("DNameConstraints.Title"));
        initComponents();
    }

    /**
     * Creates a new DNameConstraints dialog.
     *
     * @param parent The parent dialog
     * @param value  Name Constraints DER-encoded
     * @throws IOException If value could not be decoded
     */
    public DNameConstraints(JDialog parent, byte[] value) throws IOException {
        super(parent);
        setTitle(res.getString("DNameConstraints.Title"));
        initComponents();
        prepopulateWithValue(value);
    }

    private void initComponents() {
        jlPermittedSubtrees = new JLabel(res.getString("DNameConstraints.jlPermittedSubtrees.text"));

        jgsPermittedSubtrees = new JGeneralSubtrees(res.getString("DNameConstraints.PermittedSubtrees.Title"));
        jgsPermittedSubtrees.setToolTipText(res.getString("DNameConstraints.jgsPermittedSubtrees.tooltip"));

        jlExcludedSubtrees = new JLabel(res.getString("DNameConstraints.jlExcludedSubtrees.text"));

        jgsExcludedSubtrees = new JGeneralSubtrees(res.getString("DNameConstraints.ExcludedSubtrees.Title"));
        jgsExcludedSubtrees.setToolTipText(res.getString("DNameConstraints.jgsExcludedSubtrees.tooltip"));

        jbOK = new JButton(res.getString("DNameConstraints.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DNameConstraints.jbCancel.text"));
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
        pane.add(jlPermittedSubtrees, "top");
        pane.add(jgsPermittedSubtrees, "wrap");
        pane.add(jlExcludedSubtrees, "top");
        pane.add(jgsExcludedSubtrees, "wrap");
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
        NameConstraints nameConstraints = NameConstraints.getInstance(value);

        if (nameConstraints.getPermittedSubtrees() != null) {
            jgsPermittedSubtrees.setGeneralSubtrees(new GeneralSubtrees(nameConstraints.getPermittedSubtrees()));
        }

        if (nameConstraints.getExcludedSubtrees() != null) {
            jgsExcludedSubtrees.setGeneralSubtrees(new GeneralSubtrees(nameConstraints.getExcludedSubtrees()));
        }
    }

    private void okPressed() {
        List<GeneralSubtree> permittedSubtrees = jgsPermittedSubtrees.getGeneralSubtrees().getGeneralSubtrees();
        List<GeneralSubtree> excludedSubtrees = jgsExcludedSubtrees.getGeneralSubtrees().getGeneralSubtrees();

        GeneralSubtree[] permittedSubtreesArray = permittedSubtrees.toArray(
                GeneralSubtree[]::new);
        GeneralSubtree[] excludedSubtreesArray = excludedSubtrees.toArray(GeneralSubtree[]::new);

        NameConstraints nameConstraints = new NameConstraints(permittedSubtreesArray, excludedSubtreesArray);

        try {
            value = nameConstraints.getEncoded(ASN1Encoding.DER);
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
        return X509ExtensionType.NAME_CONSTRAINTS.oid();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
