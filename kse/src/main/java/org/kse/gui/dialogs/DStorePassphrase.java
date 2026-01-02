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

package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;
import java.util.stream.Stream;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.secretkey.PasswordType;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.password.DGetNewPassword;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.preferences.PreferencesManager;
import org.kse.gui.preferences.data.KsePreferences;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to choose the parameters required for secret key generation. The
 * user may select a secret key algorithm and enter a key size in bits.
 */
public class DStorePassphrase extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private KsePreferences preferences = PreferencesManager.getPreferences();

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlAlgorithm;
    private JComboBox<PasswordType> jcbAlgorithm;
    private JLabel jlPassword;
    private JPasswordField jpfPassword;
    private JButton jbSetPass;
    private JButton jbCancel;
    private JButton jbOK;

    private KeyStoreType keystoreType;
    private PasswordType passwordType;

    private Password passphrase;
    private boolean success = false;

    /**
     * Creates a new DGenerateSecretKey dialog.
     *
     * @param parent        The parent frame
     * @param keystoreType  The keystore type for storing the key
     * @param passwordType  Initial password type
     */
    public DStorePassphrase(JFrame parent, KeyStoreType keystoreType, PasswordType passwordType) {
        super(parent, res.getString("DStorePassphrase.Title"), Dialog.ModalityType.DOCUMENT_MODAL);

        this.keystoreType = keystoreType;
        this.passwordType = passwordType;

        initComponents();
    }

    private void initComponents() {
        jlAlgorithm = new JLabel(res.getString("DStorePassphrase.jlAlgorithm.text"));

        jcbAlgorithm = new JComboBox<>();
        jcbAlgorithm.setToolTipText(res.getString("DStorePassphrase.jcbAlgorithm.tooltip"));

        populateAlgorithms();

        jlPassword = new JLabel(res.getString("DStorePassphrase.jlPassword.text"));

        jpfPassword = new JPasswordField();
        jpfPassword.setEditable(false);

        jbSetPass = new JButton(res.getString("DStorePassphrase.jbSetPass.text"));
        jbCancel = new JButton(res.getString("DStorePassphrase.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                CANCEL_KEY);

        jbOK = new JButton(res.getString("DStorePassphrase.jbOK.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
        pane.add(jlAlgorithm, "");
        pane.add(jcbAlgorithm, "growx, pushx, wrap");
        pane.add(jlPassword, "");
        pane.add(jpfPassword, "growx");
        pane.add(jbSetPass, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

        jbSetPass.addActionListener(evt -> setPassPressed());

        jbOK.addActionListener(evt -> okPressed());

        jbCancel.addActionListener(evt -> cancelPressed());

        setResizable(false);

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
                cancelPressed();
            }
        });

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

    private void populateAlgorithms() {
        Stream.of(PasswordType.values()).filter(skt -> keystoreType.supportsPasswordType(skt))
                .forEach(skt -> jcbAlgorithm.addItem(skt));

        jcbAlgorithm.setSelectedItem(passwordType);
    }

    /**
     * Get the password type chosen.
     *
     * @return The password type
     */
    public PasswordType getPasswordType() {
        return (PasswordType) jcbAlgorithm.getSelectedItem();
    }

    /**
     * @return The passphrase as a Password.
     */
    public Password getPassphrase() {
        return passphrase;
    }

    /**
     * Have the parameters been entered correctly?
     *
     * @return True if they have, false otherwise
     */
    public boolean isSuccessful() {
        return success;
    }

    private void setPassPressed() {
        DGetNewPassword dPassphrase = new DGetNewPassword((JFrame) getParent(),
                res.getString("DStorePassphrase.NewPassphrase.Title"), preferences);
        dPassphrase.setLocationRelativeTo(this);
        dPassphrase.setVisible(true);

        passphrase = dPassphrase.getPassword();
        if (passphrase != null) {
            jpfPassword.setText(new String(passphrase.toCharArray()));
        }
    }

    private void okPressed() {
        if (passphrase == null) {
            JOptionPane.showMessageDialog(getParent(),
                    res.getString("DStorePassphrase.NoPassphrase.message"),
                    res.getString("DStorePassphrase.Title"), JOptionPane.WARNING_MESSAGE);
            return;
        }
        success = true;
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
