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
package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreType;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to retrieve the type to use in the creation of a new KeyStore.
 */
public class DNewKeyStoreType extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlKeyStoreType;
    private JRadioButton jrbJceksKeyStore;
    private JRadioButton jrbJksKeyStore;
    private JRadioButton jrbPkcs12KeyStore;
    private JRadioButton jrbBksKeyStore;
    private JRadioButton jrbUberKeyStore;
    private JRadioButton jrbBcfksKeyStore;
    private JButton jbOK;
    private JButton jbCancel;

    private KeyStoreType keyStoreType;

    /**
     * Creates a new DNewKeyStoreType dialog.
     *
     * @param parent The parent frame
     */
    public DNewKeyStoreType(JFrame parent) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        setTitle(res.getString("DNewKeyStoreType.Title"));
        initComponents();
    }

    private void initComponents() {
        jlKeyStoreType = new JLabel(res.getString("DNewKeyStoreType.jlKeyStoreType.text"));

        jrbJceksKeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbJceksKeyStore.text"));
        PlatformUtil.setMnemonic(jrbJceksKeyStore,
                                 res.getString("DNewKeyStoreType.jrbJceksKeyStore.mnemonic").charAt(0));
        jrbJceksKeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbJceksKeyStore.tooltip"));

        jrbJksKeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbJksKeyStore.text"));
        PlatformUtil.setMnemonic(jrbJksKeyStore, res.getString("DNewKeyStoreType.jrbJksKeyStore.mnemonic").charAt(0));
        jrbJksKeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbJksKeyStore.tooltip"));

        jrbPkcs12KeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbPkcs12KeyStore.text"), true);
        PlatformUtil.setMnemonic(jrbPkcs12KeyStore,
                                 res.getString("DNewKeyStoreType.jrbPkcs12KeyStore.mnemonic").charAt(0));
        jrbPkcs12KeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbPkcs12KeyStore.tooltip"));

        jrbBksKeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbBksKeyStore.text"));
        PlatformUtil.setMnemonic(jrbBksKeyStore, res.getString("DNewKeyStoreType.jrbBksKeyStore.mnemonic").charAt(0));
        jrbBksKeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbBksKeyStore.tooltip"));

        jrbUberKeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbUberKeyStore.text"));
        PlatformUtil.setMnemonic(jrbUberKeyStore, res.getString("DNewKeyStoreType.jrbUberKeyStore.mnemonic").charAt(0));
        jrbUberKeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbUberKeyStore.tooltip"));

        jrbBcfksKeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbBcfksKeyStore.text"));
        PlatformUtil.setMnemonic(jrbBcfksKeyStore,
                                 res.getString("DNewKeyStoreType.jrbBcfksKeyStore.mnemonic").charAt(0));
        jrbBcfksKeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbBcfksKeyStore.tooltip"));

        ButtonGroup keyStoreTypesGroup = new ButtonGroup();
        keyStoreTypesGroup.add(jrbPkcs12KeyStore);
        keyStoreTypesGroup.add(jrbJceksKeyStore);
        keyStoreTypesGroup.add(jrbJksKeyStore);
        keyStoreTypesGroup.add(jrbBksKeyStore);
        keyStoreTypesGroup.add(jrbUberKeyStore);
        keyStoreTypesGroup.add(jrbBcfksKeyStore);

        jbOK = new JButton(res.getString("DNewKeyStoreType.jbOK.text"));

        jbCancel = new JButton(res.getString("DNewKeyStoreType.jbCancel.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "", ""));
        pane.add(jlKeyStoreType, "wrap unrel");
        pane.add(jrbPkcs12KeyStore, "wrap");
        pane.add(jrbJceksKeyStore, "wrap");
        pane.add(jrbJksKeyStore, "wrap");
        pane.add(jrbBksKeyStore, "wrap");
        pane.add(jrbUberKeyStore, "wrap");
        pane.add(jrbBcfksKeyStore, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap unrel");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

        jbOK.addActionListener(evt -> okPressed());

        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    /**
     * Get the selected KeyStore type.
     *
     * @return The selected KeyStore type or null if none was selected
     */
    public KeyStoreType getKeyStoreType() {
        return keyStoreType;
    }

    private void okPressed() {
        if (jrbJceksKeyStore.isSelected()) {
            keyStoreType = KeyStoreType.JCEKS;
        } else if (jrbJksKeyStore.isSelected()) {
            keyStoreType = KeyStoreType.JKS;
        } else if (jrbPkcs12KeyStore.isSelected()) {
            keyStoreType = KeyStoreType.PKCS12;
        } else if (jrbBksKeyStore.isSelected()) {
            keyStoreType = KeyStoreType.BKS;
        } else if (jrbBcfksKeyStore.isSelected()) {
            keyStoreType = KeyStoreType.BCFKS;
        } else {
            keyStoreType = KeyStoreType.UBER;
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

    // quick ui test
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        DNewKeyStoreType dialog = new DNewKeyStoreType(new JFrame());
        DialogViewer.run(dialog);
    }
}
