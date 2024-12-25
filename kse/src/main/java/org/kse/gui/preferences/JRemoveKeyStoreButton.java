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
package org.kse.gui.preferences;

import static javax.swing.JOptionPane.showConfirmDialog;

import java.io.File;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

import org.kse.gui.passwordmanager.PasswordManager;
import org.kse.utilities.Callback;

/**
 * Button to remove the keystore file path of an associated text field from the password manager.
 */
public class JRemoveKeyStoreButton extends JButton {
    private final JTextField keystorePathField;
    private final PasswordManager passwordManager;
    private final Callback updateFormFields;

    /**
     * Constructor.
     *
     * @param keystorePathField The text field to identify the keystore file path to remove
     * @param passwordManager   The password manager to remove the keystore file path from
     * @param updateFormFields  The callback to update the form fields after the keystore file path has been removed
     */
    public JRemoveKeyStoreButton(JTextField keystorePathField, PasswordManager passwordManager,
                                 Callback updateFormFields) {
        super("Remove...");
        this.keystorePathField = keystorePathField;
        this.passwordManager = passwordManager;
        this.updateFormFields = updateFormFields;
        this.addActionListener(e -> removeKeyStoreFromPasswordManager());
    }

    private void removeKeyStoreFromPasswordManager() {
        int selected = showConfirmDialog(this.getParent(),
                                         "Do you really want to remove the passwords for this keystore from the " +
                                         "password manager?",
                                         "Remove KeyStore",
                                         JOptionPane.YES_NO_OPTION);

        if (selected != JOptionPane.YES_OPTION) {
            return;
        }

        passwordManager.removeKeyStore(new File(keystorePathField.getText()));

        updateFormFields.execute();
    }
}

