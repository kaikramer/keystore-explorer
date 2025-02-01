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
package org.kse.gui.preferences.passwordmanager;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Container class for the encrypted passwords and metadata (associated keystore file, IV etc.)
 */
public class EncryptedKeyStorePasswordData {
    private File keyStoreFile;
    private byte[] encryptedKeyStorePassword;
    private byte[] encryptedKeyStorePasswordInitVector;
    private List<KeyStoreEntryPassword> keyStoreEntryPasswords = new ArrayList<>();

    // auto-generated getters/setters

    public File getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(File keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public byte[] getEncryptedKeyStorePassword() {
        return encryptedKeyStorePassword;
    }

    public void setEncryptedKeyStorePassword(byte[] encryptedKeyStorePassword) {
        this.encryptedKeyStorePassword = encryptedKeyStorePassword;
    }

    public byte[] getEncryptedKeyStorePasswordInitVector() {
        return encryptedKeyStorePasswordInitVector;
    }

    public void setEncryptedKeyStorePasswordInitVector(byte[] encryptedKeyStorePasswordInitVector) {
        this.encryptedKeyStorePasswordInitVector = encryptedKeyStorePasswordInitVector;
    }

    public List<KeyStoreEntryPassword> getKeyStoreEntryPasswords() {
        return keyStoreEntryPasswords;
    }

    public void setKeyStoreEntryPasswords(List<KeyStoreEntryPassword> keyStoreEntryPasswords) {
        this.keyStoreEntryPasswords = keyStoreEntryPasswords;
    }
}
