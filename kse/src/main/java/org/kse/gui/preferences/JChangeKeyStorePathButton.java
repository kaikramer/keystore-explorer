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
package org.kse.gui.preferences;

import java.io.File;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.passwordmanager.PasswordManager;

/**
 * Button to update the keystore file path of an associated text field.
 */
public class JChangeKeyStorePathButton extends JButton {
    private static final long serialVersionUID = 1324616391135888291L;
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");
    private final JTextField keystorePathField;
    private final PasswordManager passwordManager;

    /**
     * Constructor.
     *
     * @param keystorePathField The text field to update the keystore file path of
     * @param passwordManager   The password manager to update the keystore file path with
     */
    public JChangeKeyStorePathButton(JTextField keystorePathField, PasswordManager passwordManager) {
        super(res.getString("DPreferences.storedPasswords.changeKeyStore.button.text"));
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
        chooser.setDialogTitle(res.getString("DPreferences.storedPasswords.changeKeyStore.chooser.title"));
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("DPreferences.storedPasswords.changeKeyStore.chooser.button"));

        int rtnValue = chooser.showOpenDialog(this.getParent());
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File newPath = chooser.getSelectedFile();

            if (newPath.equals(oldPath)) {
                return;
            }

            if (passwordManager.isKeyStorePasswordKnown(newPath)) {
                JOptionPane.showMessageDialog(this.getParent(),
                        res.getString("DPreferences.storedPasswords.changeKeyStore.ksPwdKnown.msg"),
                        res.getString("DPreferences.storedPasswords.changeKeyStore.ksPwdKnown.tit"),
                        JOptionPane.ERROR_MESSAGE);
                return;
            }

            passwordManager.getKeyStorePassword(oldPath).ifPresent(password -> {
                try {
                    KseKeyStore keyStore = KeyStoreUtil.load(newPath, new Password(password));

                    if (keyStore == null) {
                        JOptionPane.showMessageDialog(this.getParent(),
                                res.getString("DPreferences.storedPasswords.changeKeyStore.ksLoad.err.msg"),
                                res.getString("DPreferences.storedPasswords.changeKeyStore.ksLoad.err.tit"),
                                JOptionPane.ERROR_MESSAGE);
                    }

                    keystorePathField.setText(newPath.getAbsolutePath());
                    passwordManager.updateKeyStoreFilePath(oldPath, newPath);
                } catch (Exception e1) {
                    JOptionPane.showMessageDialog(this.getParent(),
                            res.getString("DPreferences.storedPasswords.changeKeyStore.ksLoad.ex.msg"),
                            res.getString("DPreferences.storedPasswords.changeKeyStore.ksLoad.ex.tit"),
                            JOptionPane.ERROR_MESSAGE);
                }
            });
        }
    }
}

