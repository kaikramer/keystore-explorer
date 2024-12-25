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
package org.kse.gui.password;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.kse.gui.components.JEscDialog;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used for entering a masked password.
 */
public class DGetPassword extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/password/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";
    private JLabel jlPassword;
    private JPasswordField jpfPassword;
    private JCheckBox jcbStoreInPasswordManager;
    private JButton jbOK;
    private JButton jbCancel;

    private boolean askUserForPasswordManager = false;
    private Password password;

    /**
     * Creates new DGetPassword dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param title  The dialog's title
     */
    public DGetPassword(JFrame parent, String title) {
        this(parent, title, false);
    }

    /**
     * Creates new DGetPassword dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param title  The dialog's title
     * @param askUserForPasswordManager Whether to show the checkbox asking the user if they want to use the pwd-mgr
     */
    public DGetPassword(JFrame parent, String title, boolean askUserForPasswordManager) {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        this.askUserForPasswordManager = askUserForPasswordManager;
        initComponents();
    }

    /**
     * Creates new DGetPassword dialog where the parent is a dialog.
     *
     * @param parent   Parent dialog
     * @param title    The dialog's title
     * @param modality Dialog modality
     * @param askUserForPasswordManager Whether to show the checkbox asking the user if they want to use the pwd-mgr
     */
    public DGetPassword(JDialog parent, String title, ModalityType modality, boolean askUserForPasswordManager) {
        super(parent, title, modality);
        this.askUserForPasswordManager = askUserForPasswordManager;
        initComponents();
    }

    private void initComponents() {
        jlPassword = new JLabel(res.getString("DGetPassword.jlPassword.text"));
        jpfPassword = new JPasswordField(15);
        jpfPassword.putClientProperty("JPasswordField.cutCopyAllowed", true);

        jcbStoreInPasswordManager = new JCheckBox(res.getString("DGetPassword.jcbStoreInPasswordManager.text"));
        jcbStoreInPasswordManager.setSelected(true);
        jcbStoreInPasswordManager.setVisible(askUserForPasswordManager);

        jbOK = new JButton(res.getString("DGetPassword.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DGetPassword.jbCancel.text"));
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]rel[grow]", ""));
        pane.add(jlPassword, "");
        pane.add(jpfPassword, "growx, wrap unrelated");
        pane.add(jcbStoreInPasswordManager, "hidemode 3, split 2, spanx, wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap unrelated");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");


        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

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
     * Get the password set in the dialog.
     *
     * @return The password or null if none was set
     */
    public Password getPassword() {
        return password;
    }

    /**
     * Return whether user wants to use password manager or not
     * @return True if password manager is requested
     */
    public boolean isPasswordManagerWanted() {
        return jcbStoreInPasswordManager.isSelected();
    }

    private void okPressed() {
        password = new Password(jpfPassword.getPassword());
        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.run(new DGetPassword(new javax.swing.JFrame(), "Enter Password", true));
    }
}
