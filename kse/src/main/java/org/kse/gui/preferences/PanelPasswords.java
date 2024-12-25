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

import static java.text.MessageFormat.format;
import static org.kse.gui.preferences.data.PasswordGeneratorSettings.PWD_GEN_MAX_LENGTH;
import static org.kse.gui.preferences.data.PasswordGeneratorSettings.PWD_GEN_MIN_LENGTH;
import static org.kse.utilities.PRNG.SPECIAL_CHARACTERS;
import static org.kse.utilities.StringUtils.shortenString;

import java.awt.Color;
import java.io.File;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;

import org.kse.crypto.encryption.EncryptionException;
import org.kse.gui.CursorUtil;
import org.kse.gui.MiGUtil;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.DInitPasswordManager;
import org.kse.gui.passwordmanager.DUnlockPasswordManager;
import org.kse.gui.passwordmanager.PasswordManager;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.gui.preferences.data.PasswordGeneratorSettings;
import org.kse.utilities.PRNG;

import net.miginfocom.swing.MigLayout;

class PanelPasswords {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");

    private final DPreferences parent;
    private final KsePreferences preferences;

    private final JPanel jpPasswords= new JPanel();
    private JCheckBox jcbPasswordGeneratorEnabled;
    private JLabel jlLengthOfGeneratedPasswords;
    private JSpinner jsPasswordLength;
    private JCheckBox jcbIncludeLowerCaseLetters;
    private JCheckBox jcbIncludeUpperCaseLetters;
    private JCheckBox jcbIncludeDigits;
    private JCheckBox jcbIncludeSpecialCharacters;
    private JLabel jlExamplePassword;

    PanelPasswords(DPreferences parent, KsePreferences preferences) {
        this.parent = parent;
        this.preferences = preferences;
    }

    JPanel initPasswordsCard() {
        PasswordManager passwordManager = PasswordManager.getInstance();
        boolean unlocked = passwordManager.isUnlocked();
        boolean initialized = passwordManager.isInitialized();
        PasswordGeneratorSettings pwdGeneratorSettings = preferences.getPasswordGeneratorSettings();

        jcbPasswordGeneratorEnabled = new JCheckBox();
        jcbPasswordGeneratorEnabled.setText(res.getString("DPreferences.jcbPasswordGeneratorEnabled.text"));
        jcbPasswordGeneratorEnabled.setSelected(pwdGeneratorSettings.isEnabled());

        jlLengthOfGeneratedPasswords = new JLabel(res.getString("DPreferences.jlLengthOfGeneratedPasswords.text"));

        jsPasswordLength = new JSpinner(new SpinnerNumberModel(pwdGeneratorSettings.getLength(),
                                                               PWD_GEN_MIN_LENGTH, PWD_GEN_MAX_LENGTH, 1));
        jsPasswordLength.setEnabled(pwdGeneratorSettings.isEnabled());

        jcbIncludeLowerCaseLetters = new JCheckBox(
                format(res.getString("DPreferences.jcbIncludeLowerCaseLetters.text"), "a-z"));
        jcbIncludeLowerCaseLetters.setEnabled(pwdGeneratorSettings.isEnabled());
        jcbIncludeLowerCaseLetters.setSelected(pwdGeneratorSettings.isIncludeLowerCaseLetters());

        jcbIncludeUpperCaseLetters = new JCheckBox(
                format(res.getString("DPreferences.jcbIncludeUpperCaseLetters.text"), "A-Z"));
        jcbIncludeUpperCaseLetters.setEnabled(pwdGeneratorSettings.isEnabled());
        jcbIncludeUpperCaseLetters.setSelected(pwdGeneratorSettings.isIncludeUpperCaseLetters());

        jcbIncludeDigits = new JCheckBox(format(res.getString("DPreferences.jcbIncludeDigits.text"), "0-9"));
        jcbIncludeDigits.setEnabled(pwdGeneratorSettings.isEnabled());
        jcbIncludeDigits.setSelected(pwdGeneratorSettings.isIncludeDigits());

        jcbIncludeSpecialCharacters = new JCheckBox(
                format(res.getString("DPreferences.jcbIncludeSpecialCharacters.text"), SPECIAL_CHARACTERS));
        jcbIncludeSpecialCharacters.setEnabled(pwdGeneratorSettings.isEnabled());
        jcbIncludeSpecialCharacters.setSelected(pwdGeneratorSettings.isIncludeSpecialCharacters());

        jlExamplePassword = new JLabel(createExamplePassword());

        JButton jbInitialize = new JButton(res.getString("DPreferences.jbInitialize.text"));
        jbInitialize.setEnabled(!initialized);

        JButton jbUnlock = new JButton(res.getString("DPreferences.jbUnlock.text"));
        jbUnlock.setEnabled(initialized && !unlocked);

        // layout
        jpPasswords.setLayout(new MigLayout("insets dialog", "20lp[][]", "20lp[][]"));
        MiGUtil.addSeparator(jpPasswords, res.getString("DPreferences.passwordGenerator.separator"));
        jpPasswords.add(jcbPasswordGeneratorEnabled, "gapx indent, spanx 2");
        jpPasswords.add(jlLengthOfGeneratedPasswords, "spanx, split 2");
        jpPasswords.add(jsPasswordLength, "wrap");
        jpPasswords.add(jcbIncludeLowerCaseLetters, "gapx indent, spanx 2");
        jpPasswords.add(jcbIncludeUpperCaseLetters, "wrap");
        jpPasswords.add(jcbIncludeDigits, "gapx indent, spanx 2");
        jpPasswords.add(jcbIncludeSpecialCharacters, "spanx, wrap unrel");
        jpPasswords.add(jlExamplePassword, "gapx indent, spanx, wrap para");
        MiGUtil.addSeparator(jpPasswords, res.getString("DPreferences.passwordManagerStatus.separator"));
        jpPasswords.add(new JLabel(initialized ? res.getString("DPreferences.passwordManagerStatusInitialized.text")
                                               : res.getString("DPreferences.passwordManagerStatusNotInitialized.text")),
                        "gapx indent");
        jpPasswords.add(jbInitialize, "sg status, wrap");
        jpPasswords.add(new JLabel(unlocked ? res.getString("DPreferences.passwordManagerStatusUnlocked.text")
                                            : res.getString("DPreferences.passwordManagerStatusLocked.text")),
                        "gapx indent");
        jpPasswords.add(jbUnlock, "sg status, wrap para");
        MiGUtil.addSeparator(jpPasswords, res.getString("DPreferences.storedPasswords.separator"));
        listKeyStoresInPasswordManager(passwordManager, unlocked);

        // actions
        jcbPasswordGeneratorEnabled.addItemListener(evt -> updatePasswordGeneratorComponents());
        jsPasswordLength.addChangeListener(evt -> jlExamplePassword.setText(createExamplePassword()));
        jcbIncludeDigits.addItemListener(evt -> jlExamplePassword.setText(createExamplePassword()));
        jcbIncludeLowerCaseLetters.addItemListener(evt -> jlExamplePassword.setText(createExamplePassword()));
        jcbIncludeUpperCaseLetters.addItemListener(evt -> jlExamplePassword.setText(createExamplePassword()));
        jcbIncludeSpecialCharacters.addItemListener(evt -> jlExamplePassword.setText(createExamplePassword()));
        jbUnlock.addActionListener(e -> {
            try {
                CursorUtil.setCursorBusy(parent);
                unlockPasswordManager(passwordManager);
            } finally {
                CursorUtil.setCursorFree(parent);
            }
        });
        jbInitialize.addActionListener(e -> {
            try {
                CursorUtil.setCursorBusy(parent);
                initializePasswordManager(passwordManager);
            } finally {
                CursorUtil.setCursorFree(parent);
            }
        });

        return jpPasswords;
    }

    private void listKeyStoresInPasswordManager(PasswordManager passwordManager, boolean unlocked) {
        if (!passwordManager.isInitialized() || passwordManager.getKnownKeyStorePasswordList().isEmpty()) {
            jpPasswords.add(new JLabel(res.getString("DPreferences.storedPasswords.none.text")), "spanx, gapx indent");
            return;
        }

        for (File keyStoreFile : passwordManager.getKnownKeyStorePasswordList()) {
            jpPasswords.add(new JLabel(res.getString("DPreferences.storedPasswords.keyStore.text")), "gapx indent");
            JTextField jtfKeyStorePath = createKeyStorePathField(keyStoreFile, 30);
            if (!keyStoreFile.exists()) jtfKeyStorePath.setForeground(Color.RED);
            jpPasswords.add(jtfKeyStorePath, "span 2, growx");

            var jbChangeKeyStorePath = new JChangeKeyStorePathButton(jtfKeyStorePath, passwordManager);
            jbChangeKeyStorePath.setEnabled(unlocked);
            jpPasswords.add(jbChangeKeyStorePath, "sizegroupx");

            var jbRemoveKeyStore = new JRemoveKeyStoreButton(jtfKeyStorePath, passwordManager,
                                                             this::updatePasswordsCard);
            jpPasswords.add(jbRemoveKeyStore, "sizegroupx, wrap");

            jpPasswords.add(new JLabel(res.getString("DPreferences.storedPasswords.keyStorePassword.text")), "skip");
            char[] ksPassword = passwordManager.getKeyStorePassword(keyStoreFile).orElse(null);
            JPasswordField jpfKeyStore = createPasswordField(ksPassword, 20);
            jpPasswords.add(jpfKeyStore, "");

            JToggleDisplayPasswordButton jtpKeyStore = new JToggleDisplayPasswordButton(jpfKeyStore);
            jtpKeyStore.setEnabled(unlocked);
            jpPasswords.add(jtpKeyStore, "sizegroupx");

            JCopyPasswordButton jcpbKeyStore = new JCopyPasswordButton(jpfKeyStore);
            jcpbKeyStore.setEnabled(unlocked);
            jpPasswords.add(jcpbKeyStore, "sizegroupx, wrap");

            listEntryPasswords(keyStoreFile, passwordManager, unlocked);
        }
    }

    private void listEntryPasswords(File keyStoreFile, PasswordManager passwordManager, boolean unlocked) {
        for (String alias : passwordManager.getAliasList(keyStoreFile)) {
            jpPasswords.add(new JLabel(format(res.getString("DPreferences.storedPasswords.entry.text"),
                                              shortenString(alias, 12))), "skip");
            char[] password = passwordManager.getKeyStoreEntryPassword(keyStoreFile, alias).orElse(null);
            JPasswordField jpfEntry = createPasswordField(password, 20);
            jpPasswords.add(jpfEntry, "");

            JToggleDisplayPasswordButton jtpbEntry = new JToggleDisplayPasswordButton(jpfEntry);
            jtpbEntry.setEnabled(unlocked);
            jpPasswords.add(jtpbEntry, "sizegroupx");

            JCopyPasswordButton jcpbEntry = new JCopyPasswordButton(jpfEntry);
            jcpbEntry.setEnabled(unlocked);
            jpPasswords.add(jcpbEntry, "sizegroupx, wrap");
        }
    }

    private String createExamplePassword() {
        PasswordGeneratorSettings pwdGeneratorSettings = new PasswordGeneratorSettings();
        pwdGeneratorSettings.setLength((((Number) jsPasswordLength.getValue()).intValue()));
        pwdGeneratorSettings.setIncludeLowerCaseLetters(jcbIncludeLowerCaseLetters.isSelected());
        pwdGeneratorSettings.setIncludeUpperCaseLetters(jcbIncludeUpperCaseLetters.isSelected());
        pwdGeneratorSettings.setIncludeDigits(jcbIncludeDigits.isSelected());
        pwdGeneratorSettings.setIncludeSpecialCharacters(jcbIncludeSpecialCharacters.isSelected());
        return format(res.getString("DPreferences.passwordGenerator.example.text"),
                                    new String(PRNG.generatePassword(pwdGeneratorSettings)));
    }

    private void unlockPasswordManager(PasswordManager passwordManager) {
        try {
            JFrame jFrame = (JFrame) parent.getOwner();

            var dUnlockPasswordManager = new DUnlockPasswordManager(jFrame);
            dUnlockPasswordManager.setLocationRelativeTo(jFrame);
            dUnlockPasswordManager.setVisible(true);

            if (!dUnlockPasswordManager.isCancelled()) {
                passwordManager.unlock(dUnlockPasswordManager.getPassword().toCharArray());
                updatePasswordsCard();
            }
        } catch (EncryptionException e) {
            JOptionPane.showMessageDialog(parent,
                                          res.getString("DPreferences.WrongPasswordManagerPassword.message"),
                                          res.getString("DPreferences.UnlockPasswordManager.title"),
                                          JOptionPane.WARNING_MESSAGE);
        } catch (Exception e) {
            DError.displayError(parent, e);
        }
    }

    private void initializePasswordManager(PasswordManager passwordManager) {
        JFrame jFrame = (JFrame) parent.getOwner();

        var dInitPasswordManager = new DInitPasswordManager(jFrame, preferences.getPasswordQualityConfig());
        dInitPasswordManager.setLocationRelativeTo(jFrame);
        dInitPasswordManager.setVisible(true);

        if (dInitPasswordManager.getPassword() != null) {
            passwordManager.unlock(dInitPasswordManager.getPassword().toCharArray());
            passwordManager.save();
            updatePasswordsCard();
        }
    }

    private void updatePasswordGeneratorComponents() {
        jlLengthOfGeneratedPasswords.setEnabled(jcbPasswordGeneratorEnabled.isSelected());
        jsPasswordLength.setEnabled(jcbPasswordGeneratorEnabled.isSelected());
        jcbIncludeLowerCaseLetters.setEnabled(jcbPasswordGeneratorEnabled.isSelected());
        jcbIncludeUpperCaseLetters.setEnabled(jcbPasswordGeneratorEnabled.isSelected());
        jcbIncludeDigits.setEnabled(jcbPasswordGeneratorEnabled.isSelected());
        jcbIncludeSpecialCharacters.setEnabled(jcbPasswordGeneratorEnabled.isSelected());
        jlExamplePassword.setEnabled(jcbPasswordGeneratorEnabled.isSelected());
    }

    private void updatePasswordsCard() {
        jpPasswords.removeAll();
        initPasswordsCard();
        jpPasswords.revalidate();
        jpPasswords.repaint();
    }

    private static JTextField createKeyStorePathField(File keyStoreFiles, int size) {
        JTextField jtfKeyStorePath = new JTextField(size);
        jtfKeyStorePath.setEditable(false);
        jtfKeyStorePath.setText(keyStoreFiles.getAbsolutePath());
        return jtfKeyStorePath;
    }

    private static JPasswordField createPasswordField(char[] password, int size) {
        JPasswordField jpfKeyStorePassword = new JPasswordField(size);
        jpfKeyStorePassword.setEnabled(false);
        jpfKeyStorePassword.setText(password == null ? "********************" : new String(password));
        return jpfKeyStorePassword;
    }

    public JCheckBox getJcbPasswordGeneratorEnabled() {
        return jcbPasswordGeneratorEnabled;
    }

    public JSpinner getJsPasswordLength() {
        return jsPasswordLength;
    }

    public JCheckBox getJcbIncludeLowerCaseLetters() {
        return jcbIncludeLowerCaseLetters;
    }

    public JCheckBox getJcbIncludeUpperCaseLetters() {
        return jcbIncludeUpperCaseLetters;
    }

    public JCheckBox getJcbIncludeDigits() {
        return jcbIncludeDigits;
    }

    public JCheckBox getJcbIncludeSpecialCharacters() {
        return jcbIncludeSpecialCharacters;
    }
}
