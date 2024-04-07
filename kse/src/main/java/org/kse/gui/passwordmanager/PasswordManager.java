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
package org.kse.gui.passwordmanager;

import static java.util.stream.Collectors.toMap;
import static org.kse.crypto.pbkd.PasswordBasedKeyDerivation.deriveKeyWithArgon2id;
import static org.kse.crypto.pbkd.PasswordBasedKeyDerivation.deriveKeyWithPbkdf2;
import static org.kse.gui.passwordmanager.EncryptionAlgorithm.AES_CBC;
import static org.kse.gui.passwordmanager.KeyDerivationAlgorithm.PBKDF2;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.kse.crypto.encryption.AES;
import org.kse.gui.preferences.PreferencesManager;
import org.kse.gui.preferences.passwordmanager.EncryptedKeyStorePasswordData;
import org.kse.gui.preferences.passwordmanager.EncryptedKeyStorePasswords;
import org.kse.gui.preferences.passwordmanager.KeyDerivationSettings;
import org.kse.gui.preferences.passwordmanager.KeyStoreEntryPassword;
import org.kse.utilities.PRNG;

/**
 * This class is responsible for encrypting and decrypting keystore and keystore entry passwords, storing them and
 * providing them for unlocking keystores and keystore entries.
 */
public class PasswordManager {

    private static PasswordManager INSTANCE;
    private char[] mainPassword;
    private boolean unlocked = false;
    private List<KeyStorePasswordData> keyStorePasswords = new ArrayList<>();

    /**
     * Get singleton instance of PasswordManager
     * @return PasswordManager instance
     */
    public static PasswordManager getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new PasswordManager();
        }
        return INSTANCE;
    }

    /**
     * Checks if a password for the given keystore file has been stored in the password manager
     *
     * @param keyStoreFile keystore file path
     * @return True, if password is available
     */
    public boolean isKeyStorePasswordKnown(File keyStoreFile) {
        return PreferencesManager.getKeyStorePasswords()
                                 .getPasswords()
                                 .stream()
                                 .anyMatch(d -> d.getKeyStoreFile().equals(keyStoreFile));
    }

    /**
     * Returns whether the password manager has been initialized (i.e. a main password was entered and a configuration
     * has been created)
     *
     * @return True if password manager has been initialized
     */
    public boolean isInitialized() {
        return PreferencesManager.getKeyStorePasswords().getKeyDerivationSettings().getSalt() != null;
    }

    /**
     * Returns whether the user has already unlocked the encrypted passwords
     *
     * @return True if password manager has been unlocked (passwords have been decrypted)
     */
    public boolean isUnlocked() {
        return unlocked;
    }

    /**
     * Unlock password manager (this tries to de-encrypt all the passwords from the configuration file)
     *
     * @param passwordManagerMainPassword The password used to decrypt the keystore passwords
     */
    public void unlock(char[] passwordManagerMainPassword) {
        if (unlocked) return;
        mainPassword = passwordManagerMainPassword.clone();
        keyStorePasswords = decryptPasswords(PreferencesManager.getKeyStorePasswords(), mainPassword);
        unlocked = true;
    }

    /**
     * Return stored keystore password
     *
     * @param keyStoreFile File name and path of the keystore
     * @return keystore password - if found
     */
    public Optional<char[]> getKeyStorePassword(File keyStoreFile) {
        return keyStorePasswords.stream()
                                .filter(d -> d.getKeyStoreFile().equals(keyStoreFile))
                                .map(KeyStorePasswordData::getKeyStorePassword)
                                .filter(Objects::nonNull)
                                .map(char[]::clone)
                                .findFirst();
    }

    /**
     * Return entry password
     *
     * @param keyStoreFile File name and path of the keystore
     * @param alias Alias of the keystore entry
     * @return keystore entry password - if found
     */
    public Optional<char[]> getKeyStoreEntryPassword(File keyStoreFile, String alias) {
        return keyStorePasswords.stream()
                                .filter(d -> d.getKeyStoreFile().equals(keyStoreFile))
                                .map(p -> p.getKeyStoreEntryPasswords().get(alias))
                                .filter(Objects::nonNull)
                                .map(char[]::clone)
                                .findFirst();
    }

    /**
     * Add or replace the given keystore password data
     *
     */
    public void update(File keyStoreFile, char[] keyStorePassword, Map<String, char[]> entryPasswords) {
        KeyStorePasswordData data = new KeyStorePasswordData();
        data.setKeyStoreFile(keyStoreFile);
        data.setKeyStorePassword(keyStorePassword.clone());

        // fetch existing data first, because we have to merge it with the updates
        KeyStorePasswordData oldData = keyStorePasswords.stream()
                                                                     .filter(d -> d.getKeyStoreFile()
                                                                                   .equals(keyStoreFile))
                                                                     .findFirst()
                                                                     .orElse(new KeyStorePasswordData());

        // the passed entry password list contains only unlocked entries, but there might be more in the keystore;
        // so we add the old entry data first and then overwrite/update them or add new ones
        oldData.getKeyStoreEntryPasswords().forEach((a, p) -> data.getKeyStoreEntryPasswords().put(a, p.clone()));
        entryPasswords.forEach((a, p) -> data.getKeyStoreEntryPasswords().put(a, p.clone()));

        keyStorePasswords.removeIf(data::equals);
        keyStorePasswords.add(data);
    }

    /**
     * Add or replace the given ks entry password data.
     * <p>
     * Calling this is only necessary when an existing entry is to be added to the password manager. Newly created
     * entries are automatically added when the keystore is saved.
     * </p>
     *
     * @param keyStoreFile keystore file
     * @param alias alias of entry
     * @param password password of entry
     */
    public void updateEntryPassword(File keyStoreFile, String alias, char[] password) {
        keyStorePasswords.stream()
                         .filter(d -> d.getKeyStoreFile().equals(keyStoreFile))
                         .findAny()
                         .ifPresent(data -> data.getKeyStoreEntryPasswords().put(alias, password.clone()));
    }

    /**
     * Encrypt and save passwords to the configuration file
     */
    public void save() {
        byte[] salt = PRNG.generate(16);
        int iterations = 600_000;
        int keyLengthInBits = 256;
        SecretKey key = deriveKeyWithPbkdf2(mainPassword, salt, iterations, keyLengthInBits);

        var keyDerivationSettings = new KeyDerivationSettings();
        keyDerivationSettings.setKeyDerivationAlgorithm(PBKDF2);
        keyDerivationSettings.setSalt(salt);
        keyDerivationSettings.setIterations(iterations);
        keyDerivationSettings.setDerivedKeyLength(keyLengthInBits);

        EncryptedKeyStorePasswords encryptedKeyStorePasswords = PreferencesManager.getKeyStorePasswords();
        encryptedKeyStorePasswords.setKeyDerivationSettings(keyDerivationSettings);
        encryptedKeyStorePasswords.setEncryptionAlgorithm(AES_CBC);

        List<EncryptedKeyStorePasswordData> passwords = new ArrayList<>();
        keyStorePasswords.forEach(p -> passwords.add(createEncryptedKeyStorePasswordData(p, key)));
        encryptedKeyStorePasswords.setPasswords(passwords);

        PreferencesManager.persistKeyStorePasswords();
    }

    private List<KeyStorePasswordData> decryptPasswords(EncryptedKeyStorePasswords encryptedKeyStorePasswords,
                                                        char[] mainPassword) {
        var passwordData = new ArrayList<KeyStorePasswordData>();

        if (!isInitialized()) {
            return passwordData;
        }

        SecretKey key = deriveKey(encryptedKeyStorePasswords, mainPassword);

        for (EncryptedKeyStorePasswordData encryptedPwdData : encryptedKeyStorePasswords.getPasswords()) {
            byte[] decryptedPassword = AES.decryptAesCbc(encryptedPwdData.getEncryptedKeyStorePassword(),
                                                         encryptedPwdData.getEncryptedKeyStorePasswordInitVector(),
                                                         key);

            var keyStorePasswordData = new KeyStorePasswordData();
            keyStorePasswordData.setKeyStoreFile(encryptedPwdData.getKeyStoreFile());
            keyStorePasswordData.setKeyStorePassword(new String(decryptedPassword).toCharArray());
            keyStorePasswordData.setKeyStoreEntryPasswords(decryptEntryPasswords(encryptedPwdData, key));

            passwordData.add(keyStorePasswordData);
        }

        return passwordData;
    }

    private static SecretKey deriveKey(EncryptedKeyStorePasswords encryptedKeyStorePasswords, char[] mainPassword) {
        KeyDerivationSettings kdfSettings = encryptedKeyStorePasswords.getKeyDerivationSettings();
        if (kdfSettings.getKeyDerivationAlgorithm() == PBKDF2) {
            return deriveKeyWithPbkdf2(mainPassword,
                                       kdfSettings.getSalt(),
                                       kdfSettings.getIterations(),
                                       kdfSettings.getDerivedKeyLength());
        } else {
            return deriveKeyWithArgon2id(mainPassword,
                                         kdfSettings.getSalt(),
                                         kdfSettings.getIterations(),
                                         kdfSettings.getMemLimitInMB(),
                                         kdfSettings.getParallelism(),
                                         kdfSettings.getDerivedKeyLength());
        }
    }

    private static Map<String, char[]> decryptEntryPasswords(EncryptedKeyStorePasswordData encrPwdData, SecretKey key) {
        return encrPwdData.getKeyStoreEntryPasswords()
                          .stream()
                          .collect(toMap(KeyStoreEntryPassword::getEntryAlias,
                                         e -> new String(AES.decryptAesCbc(e.getEncryptedKeyEntryPassword(),
                                                                           e.getEncryptedKeyEntryPasswordInitVector(),
                                                                           key)).toCharArray()));
    }

    private EncryptedKeyStorePasswordData createEncryptedKeyStorePasswordData(KeyStorePasswordData pwdData,
                                                                              SecretKey key) {
        byte[] iv = PRNG.generate(16);

        byte[] encryptedKeyStorePwd = AES.encryptAesCbc(new String(pwdData.getKeyStorePassword()).getBytes(), iv, key);
        var encryptedEntryPwds = pwdData.getKeyStoreEntryPasswords()
                                        .entrySet()
                                        .stream()
                                        .map(e -> createEncryptedEntryPwd(e.getKey(), e.getValue(), key))
                                        .collect(Collectors.<KeyStoreEntryPassword>toList());

        var encryptedKeyStorePasswordData = new EncryptedKeyStorePasswordData();
        encryptedKeyStorePasswordData.setKeyStoreFile(pwdData.getKeyStoreFile());
        encryptedKeyStorePasswordData.setEncryptedKeyStorePassword(encryptedKeyStorePwd);
        encryptedKeyStorePasswordData.setEncryptedKeyStorePasswordInitVector(iv);
        encryptedKeyStorePasswordData.setKeyStoreEntryPasswords(encryptedEntryPwds);
        return encryptedKeyStorePasswordData;
    }

    private KeyStoreEntryPassword createEncryptedEntryPwd(String alias, char[] password, SecretKey key) {
        byte[] iv = PRNG.generate(16);
        var entryPassword = new KeyStoreEntryPassword();
        entryPassword.setEntryAlias(alias);
        entryPassword.setEncryptedKeyEntryPassword(AES.encryptAesCbc(new String(password).getBytes(), iv, key));
        entryPassword.setEncryptedKeyEntryPasswordInitVector(iv);
        return entryPassword;
    }
}
