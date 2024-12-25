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

import java.io.File;
import java.security.KeyStore;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.passwordmanager.PasswordManager;

/**
 * Button to update the keystore file path of an associated text field.
 */
public class JChangeKeyStorePathButton extends JButton {
    private final JTextField keystorePathField;
    private final PasswordManager passwordManager;

    /**
     * Constructor.
     *
     * @param keystorePathField The text field to update the keystore file path of
     * @param passwordManager   The password manager to update the keystore file path with
     */
    public JChangeKeyStorePathButton(JTextField keystorePathField, PasswordManager passwordManager) {
        super("Change...");
        this.keystorePathField = keystorePathField;
        this.passwordManager = passwordManager;
        this.addActionListener(e -> {
            try {
                CursorUtil.setCursorBusy(this);
                changeKeyStorePath();
            } finally {
                CursorUtil.setCursorFree(this);
            }
        });
    }

    private void changeKeyStorePath() {
        File oldPath = new File(keystorePathField.getText());

        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();
        chooser.setCurrentDirectory(oldPath.getParentFile());
        chooser.setDialogTitle("Select KeyStore File");
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText("Select");

        int rtnValue = chooser.showOpenDialog(this.getParent());
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File newPath = chooser.getSelectedFile();

            if (newPath.equals(oldPath)) {
                return;
            }

            if (passwordManager.isKeyStorePasswordKnown(newPath)) {
                JOptionPane.showMessageDialog(this.getParent(),
                                              "The selected KeyStore file is already stored in the password manager.",
                                              "KeyStore file already in password manager",
                                              JOptionPane.ERROR_MESSAGE);
                return;
            }

            passwordManager.getKeyStorePassword(oldPath).ifPresent(password -> {
                try {
                    KeyStore keyStore = KeyStoreUtil.load(newPath, new Password(password));

                    if (keyStore == null) {
                        JOptionPane.showMessageDialog(this.getParent(),
                                                      "File does not seem to be a keystore.",
                                                      "Error opening KeyStore",
                                                      JOptionPane.ERROR_MESSAGE);
                    }

                    keystorePathField.setText(newPath.getAbsolutePath());
                    passwordManager.updateKeyStoreFilePath(oldPath, newPath);
                } catch (Exception e1) {
                    JOptionPane.showMessageDialog(this.getParent(),
                                                  "Cannot open keystore with the password stored for the old path.",
                                                  "Error opening KeyStore",
                                                  JOptionPane.ERROR_MESSAGE);
                }
            });
        }
    }
}

