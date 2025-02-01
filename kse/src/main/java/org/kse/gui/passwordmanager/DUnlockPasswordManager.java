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
package org.kse.gui.passwordmanager;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.kse.gui.components.JEscDialog;
import org.kse.gui.components.JMultiLineLabel;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used for initialising the KSE Password Manager
 */
public class DUnlockPasswordManager extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/passwordmanager/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JMultiLineLabel jmllExplanations;
    private JLabel jlPassword;
    private JPasswordField jpfPassword;
    private JButton jbOK;
    private JButton jbCancel;

    private boolean cancelled = false;

    /**
     * Creates new DUnlockPasswordManager dialog where the parent is a frame.
     *
     * @param parent                Parent frame
     */
    public DUnlockPasswordManager(JFrame parent) {
        super(parent, res.getString("DUnlockPasswordManager.Title"), ModalityType.DOCUMENT_MODAL);
        initComponents();
    }

    /**
     * Creates new DUnlockPasswordManager dialog where the parent is a dialog.
     *
     * @param parent                Parent dialog
     */
    public DUnlockPasswordManager(JDialog parent) {
        super(parent, res.getString("DUnlockPasswordManager.Title"), ModalityType.DOCUMENT_MODAL);
        initComponents();
    }

    private void initComponents() {
        jmllExplanations = new JMultiLineLabel(res.getString("DUnlockPasswordManager.jmllExplanations.text"));

        jlPassword = new JLabel(res.getString("DUnlockPasswordManager.jlFirst.text"));
        jpfPassword = new JPasswordField(15);

        jbOK = new JButton(res.getString("DUnlockPasswordManager.jbOK.text"));

        jbCancel = new JButton(res.getString("DUnlockPasswordManager.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]rel[grow]", ""));
        pane.add(jmllExplanations, "growx, spanx, wrap unrelated");
        pane.add(jlPassword, "");
        pane.add(jpfPassword, "growx, wrap related");
        pane.add(new JSeparator(), "spanx, growx, wrap unrelated");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

        jbOK.addActionListener(evt -> okPressed());

        jbCancel.addActionListener(evt -> cancelPressed());
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

        SwingUtilities.invokeLater(() -> jpfPassword.requestFocus());
    }

    /**
     * Get the password set in the dialog.
     *
     * @return The password or null if none was set
     */
    public Password getPassword() {
        return new Password(jpfPassword.getPassword());
    }

    /**
     * Was dialog cancelled?
     * @return True if cancel button was clicked
     */
    public boolean isCancelled() {
        return cancelled;
    }

    private void okPressed() {
        closeDialog();
    }

    private void cancelPressed() {
        cancelled = true;
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.run(new DUnlockPasswordManager(new JFrame()));
    }
}
