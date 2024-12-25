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
package org.kse.gui.preferences.passwordmanager;

import java.util.ArrayList;
import java.util.List;

import org.kse.gui.passwordmanager.EncryptionAlgorithm;

/**
 * The password manager data (encrypted passwords, associated keystore files and encryption settings).
 * <p>
 * This is written to a JSON file as part of the KSE configuration files.
 */
public class EncryptedKeyStorePasswords {
    private int version = 2;
    private KeyDerivationSettings keyDerivationSettings = new KeyDerivationSettings();
    private EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.AES_CBC;
    private byte[] encryptionKey;
    private byte[] encryptionKeyInitVector;
    private List<EncryptedKeyStorePasswordData> passwords = new ArrayList<>();

    // auto-generated getters/setters

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public KeyDerivationSettings getKeyDerivationSettings() {
        return keyDerivationSettings;
    }

    public void setKeyDerivationSettings(KeyDerivationSettings keyDerivationSettings) {
        this.keyDerivationSettings = keyDerivationSettings;
    }

    public List<EncryptedKeyStorePasswordData> getPasswords() {
        return passwords;
    }

    public void setPasswords(List<EncryptedKeyStorePasswordData> passwords) {
        this.passwords = passwords;
    }

    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public byte[] getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(byte[] encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public byte[] getEncryptionKeyInitVector() {
        return encryptionKeyInitVector;
    }

    public void setEncryptionKeyInitVector(byte[] encryptionKeyInitVector) {
        this.encryptionKeyInitVector = encryptionKeyInitVector;
    }
}
