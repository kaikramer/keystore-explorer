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
import static org.kse.gui.passwordmanager.EncryptionAlgorithm.AES_GCM;
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
    public static final int KEY_LENGTH_BITS = 256;
    public static final int KDF_ITERATIONS = 600_000;
    public static final int SALT_LENGTH_BYTES = 16;
    public static final int IV_LENGTH_GCM_BYTES = 12;
    public static final int IV_LENGTH_CBC_BYTES = 16;

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
     * Checks if a password for the given keystore file has been stored in the password manager.
     * <p>
     * It is not necessary for the password manager to be unlocked for this to work.
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
     * Returns list of keystore files with passwords stored by the password manager.
     * <p>
     * It is not necessary for the password manager to be unlocked for this to work.
     *
     * @return List of keystore files with passwords stored by the password manager.
     */
    public List<File> getKnownKeyStorePasswordList() {
        return PreferencesManager.getKeyStorePasswords()
                                 .getPasswords()
                                 .stream()
                                 .map(EncryptedKeyStorePasswordData::getKeyStoreFile)
                                 .collect(Collectors.toList());
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
     * Get copy of current KDF settings from configuration.
     * @return KDF settings
     */
    public KeyDerivationSettings getKeyDerivationSettings() {
        return new KeyDerivationSettings(PreferencesManager.getKeyStorePasswords().getKeyDerivationSettings());
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
     * Returns a list of aliases for a certain keystore file.
     * <p>
     * It is not necessary for the password manager to be unlocked for this to work.
     *
     * @param keyStoreFile A keystore managed by this password manager.
     * @return All aliases with a managed password of this keystore.
     */
    public List<String> getAliasList(File keyStoreFile) {
        return PreferencesManager.getKeyStorePasswords()
                                 .getPasswords()
                                 .stream()
                                 .filter(d -> d.getKeyStoreFile().equals(keyStoreFile))
                                 .flatMap(d -> d.getKeyStoreEntryPasswords().stream())
                                 .map(KeyStoreEntryPassword::getEntryAlias)
                                 .collect(Collectors.toList());
    }

    /**
     * Add or replace the given keystore password data
     *
     * @param keyStoreFile Keystore file
     * @param keyStorePassword Password of keystore
     * @param entryPasswords Map of entry aliases and their passwords
     */
    public void update(File keyStoreFile, char[] keyStorePassword, Map<String, char[]> entryPasswords) {
        KeyStorePasswordData newData = new KeyStorePasswordData();
        newData.setKeyStoreFile(keyStoreFile);
        newData.setKeyStorePassword(keyStorePassword.clone());

        // fetch existing data first, because we have to merge it with the updates
        KeyStorePasswordData oldData = keyStorePasswords.stream()
                                                                     .filter(d -> d.getKeyStoreFile()
                                                                                   .equals(keyStoreFile))
                                                                     .findFirst()
                                                                     .orElse(new KeyStorePasswordData());

        // the passed entry password list contains only unlocked entries, but there might be more in the keystore;
        // so we add the old entry data first and then overwrite/update them or add new ones
        oldData.getKeyStoreEntryPasswords().forEach((a, p) -> newData.getKeyStoreEntryPasswords().put(a, p.clone()));
        entryPasswords.forEach((a, p) -> newData.getKeyStoreEntryPasswords().put(a, p.clone()));

        keyStorePasswords.removeIf(newData::equals);
        keyStorePasswords.add(newData);
    }

    /**
     * Remove the given keystore password data
     * <p>
     * It is not necessary for the password manager to be unlocked for this to work.
     *
     * @param keyStoreFile Keystore file
     */
    public void removeKeyStore(File keyStoreFile) {
        keyStorePasswords.removeIf(d -> d.getKeyStoreFile().equals(keyStoreFile));
        PreferencesManager.getKeyStorePasswords()
                          .getPasswords()
                          .removeIf(d -> d.getKeyStoreFile().equals(keyStoreFile));

        if (!unlocked) {
            // we have to persist the passwords here, because save() is not called when the password manager is locked
            PreferencesManager.persistKeyStorePasswords();
        }
    }

    /**
     * Update the path of the keystore file
     * <p>
     * It is not necessary for the password manager to be unlocked for this to work.
     *
     * @param oldPath Old path of the keystore file
     * @param newPath New path of the keystore file
     */
    public void updateKeyStoreFilePath(File oldPath, File newPath) {
        keyStorePasswords.stream()
                         .filter(d -> d.getKeyStoreFile().equals(oldPath))
                         .forEach(d -> d.setKeyStoreFile(newPath));
        PreferencesManager.getKeyStorePasswords()
                          .getPasswords()
                          .stream()
                          .filter(d -> d.getKeyStoreFile().equals(oldPath))
                          .forEach(d -> d.setKeyStoreFile(newPath));
    }

    /**
     * Add or replace the given ks entry password data.
     * <p>
     * Calling this is only necessary when an existing keystore entry is added to the password manager.
     * Newly created entries are automatically added when the keystore is saved.
     * </p>
     *
     * @param keyStoreFile Keystore file
     * @param alias Alias of entry
     * @param password Password of entry
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
    @SuppressWarnings("ConstantValue")
    public void save() {
        // use recommendations for PBKDF2 from NIST SP 800-132 for now and maybe make this configurable later
        int iterations = KDF_ITERATIONS;
        int keyLengthInBits = KEY_LENGTH_BITS;
        byte[] salt = PRNG.generate(SALT_LENGTH_BYTES);
        EncryptionAlgorithm encrAlgorithm = AES_GCM;

        SecretKey kek = deriveKeyWithPbkdf2(mainPassword, salt, iterations, keyLengthInBits);

        // generate new AES key for encryption of passwords
        SecretKey key = AES.generateKey(KEY_LENGTH_BITS);
        byte[] iv = PRNG.generate(encrAlgorithm == AES_GCM ? IV_LENGTH_GCM_BYTES : IV_LENGTH_CBC_BYTES);
        byte[] encryptedEncryptionKey = encryptKey(key, iv, kek, encrAlgorithm);

        var keyDerivationSettings = new KeyDerivationSettings();
        keyDerivationSettings.setKeyDerivationAlgorithm(PBKDF2);
        keyDerivationSettings.setSalt(salt);
        keyDerivationSettings.setIterations(iterations);
        keyDerivationSettings.setDerivedKeyLength(keyLengthInBits);

        EncryptedKeyStorePasswords encryptedKeyStorePasswords = PreferencesManager.getKeyStorePasswords();
        encryptedKeyStorePasswords.setKeyDerivationSettings(keyDerivationSettings);
        encryptedKeyStorePasswords.setEncryptionAlgorithm(encrAlgorithm);
        encryptedKeyStorePasswords.setVersion(2);
        encryptedKeyStorePasswords.setEncryptionKey(encryptedEncryptionKey);
        encryptedKeyStorePasswords.setEncryptionKeyInitVector(iv);

        List<EncryptedKeyStorePasswordData> passwords = new ArrayList<>();
        keyStorePasswords.forEach(p -> passwords.add(createEncryptedKeyStorePasswordData(p, key, encrAlgorithm)));
        encryptedKeyStorePasswords.setPasswords(passwords);

        PreferencesManager.persistKeyStorePasswords();
    }

    private byte[] encryptKey(SecretKey key, byte[] iv, SecretKey kek, EncryptionAlgorithm encrAlgorithm) {
        return encrAlgorithm == AES_GCM ?
               AES.encryptAesGcm(key.getEncoded(), iv, kek) :
               AES.encryptAesCbc(key.getEncoded(), iv, kek);
    }

    private List<KeyStorePasswordData> decryptPasswords(EncryptedKeyStorePasswords encryptedKeyStorePasswords,
                                                        char[] mainPassword) {
        var passwordData = new ArrayList<KeyStorePasswordData>();

        if (!isInitialized()) {
            return passwordData;
        }

        EncryptionAlgorithm encrAlgorithm = encryptedKeyStorePasswords.getEncryptionAlgorithm();
        SecretKey key = encryptedKeyStorePasswords.getVersion() == 1 ?
                        deriveKey(encryptedKeyStorePasswords, mainPassword) :
                        decryptEncryptionKey(deriveKey(encryptedKeyStorePasswords, mainPassword),
                                             encryptedKeyStorePasswords, encrAlgorithm);

        for (EncryptedKeyStorePasswordData encryptedPwdData : encryptedKeyStorePasswords.getPasswords()) {
            byte[] decryptedPassword = encrAlgorithm == AES_GCM ?
                                       AES.decryptAesGcm(encryptedPwdData.getEncryptedKeyStorePassword(),
                                                         encryptedPwdData.getEncryptedKeyStorePasswordInitVector(),
                                                         key) :
                                       AES.decryptAesCbc(encryptedPwdData.getEncryptedKeyStorePassword(),
                                                         encryptedPwdData.getEncryptedKeyStorePasswordInitVector(),
                                                         key);

            var keyStorePasswordData = new KeyStorePasswordData();
            keyStorePasswordData.setKeyStoreFile(encryptedPwdData.getKeyStoreFile());
            keyStorePasswordData.setKeyStorePassword(new String(decryptedPassword).toCharArray());
            keyStorePasswordData.setKeyStoreEntryPasswords(decryptEntryPasswords(encryptedPwdData, key, encrAlgorithm));

            passwordData.add(keyStorePasswordData);
        }

        return passwordData;
    }

    private SecretKey decryptEncryptionKey(SecretKey kek, EncryptedKeyStorePasswords encryptedKeyStorePasswords,
                                           EncryptionAlgorithm encrAlgorithm) {
        byte[] iv = encryptedKeyStorePasswords.getEncryptionKeyInitVector();
        byte[] encryptedKey = encryptedKeyStorePasswords.getEncryptionKey();
        byte[] decryptedKey = encrAlgorithm == AES_GCM ?
                              AES.decryptAesGcm(encryptedKey, iv, kek) :
                              AES.decryptAesCbc(encryptedKey, iv, kek);
        return AES.createKey(decryptedKey);
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

    private static Map<String, char[]> decryptEntryPasswords(EncryptedKeyStorePasswordData encrPwdData, SecretKey key,
                                                             EncryptionAlgorithm encrAlgorithm) {
        return encrPwdData.getKeyStoreEntryPasswords()
                          .stream()
                          .collect(toMap(KeyStoreEntryPassword::getEntryAlias,
                                         e -> decryptEntryPassword(key, encrAlgorithm, e)));
    }

    private static char[] decryptEntryPassword(SecretKey key, EncryptionAlgorithm encrAlgorithm,
                                               KeyStoreEntryPassword e) {
        return new String(encrAlgorithm == AES_GCM ?
                          AES.decryptAesGcm(e.getEncryptedKeyEntryPassword(),
                                            e.getEncryptedKeyEntryPasswordInitVector(), key) :
                          AES.decryptAesCbc(e.getEncryptedKeyEntryPassword(),
                                            e.getEncryptedKeyEntryPasswordInitVector(), key)).toCharArray();
    }

    private EncryptedKeyStorePasswordData createEncryptedKeyStorePasswordData(KeyStorePasswordData pwdData,
                                                                              SecretKey key,
                                                                              EncryptionAlgorithm encrAlgorithm) {

        byte[] iv = PRNG.generate(encrAlgorithm == AES_GCM ? IV_LENGTH_GCM_BYTES : IV_LENGTH_CBC_BYTES);
        byte[] encryptedKeyStorePwd = encrAlgorithm == AES_GCM ?
                                      AES.encryptAesGcm(new String(pwdData.getKeyStorePassword()).getBytes(), iv, key) :
                                      AES.encryptAesCbc(new String(pwdData.getKeyStorePassword()).getBytes(), iv, key);

        var encryptedEntryPwds = pwdData.getKeyStoreEntryPasswords()
                                        .entrySet()
                                        .stream()
                                        .map(e -> createEncryptedEntryPwd(e.getKey(), e.getValue(), key, encrAlgorithm))
                                        .collect(Collectors.<KeyStoreEntryPassword>toList());

        var encryptedKeyStorePasswordData = new EncryptedKeyStorePasswordData();
        encryptedKeyStorePasswordData.setKeyStoreFile(pwdData.getKeyStoreFile());
        encryptedKeyStorePasswordData.setEncryptedKeyStorePassword(encryptedKeyStorePwd);
        encryptedKeyStorePasswordData.setEncryptedKeyStorePasswordInitVector(iv);
        encryptedKeyStorePasswordData.setKeyStoreEntryPasswords(encryptedEntryPwds);
        return encryptedKeyStorePasswordData;
    }

    private KeyStoreEntryPassword createEncryptedEntryPwd(String alias, char[] password, SecretKey key,
                                                          EncryptionAlgorithm encrAlgorithm) {
        byte[] iv = PRNG.generate(encrAlgorithm == AES_GCM ? IV_LENGTH_GCM_BYTES : IV_LENGTH_CBC_BYTES);
        byte[] encryptedEntryPwd = encrAlgorithm == AES_GCM ?
                                   AES.encryptAesGcm(new String(password).getBytes(), iv, key) :
                                   AES.encryptAesCbc(new String(password).getBytes(), iv, key);

        var entryPassword = new KeyStoreEntryPassword();
        entryPassword.setEntryAlias(alias);
        entryPassword.setEncryptedKeyEntryPassword(encryptedEntryPwd);
        entryPassword.setEncryptedKeyEntryPasswordInitVector(iv);
        return entryPassword;
    }
}
