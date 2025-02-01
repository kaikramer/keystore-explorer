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

import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class KeyStorePasswordData {
    private File keyStoreFile;
    private char[] keyStorePassword;
    private Map<String, char[]> keyStoreEntryPasswords = new HashMap<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        KeyStorePasswordData that = (KeyStorePasswordData) o;

        return keyStoreFile.equals(that.keyStoreFile);
    }

    @Override
    public int hashCode() {
        int result = keyStoreFile.hashCode();
        result = 31 * result + keyStoreFile.hashCode();
        return result;
    }

    // auto-generated getters/setters

    public File getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(File keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public char[] getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(char[] keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public Map<String, char[]> getKeyStoreEntryPasswords() {
        return keyStoreEntryPasswords;
    }

    public void setKeyStoreEntryPasswords(Map<String, char[]> keyStoreEntryPasswords) {
        this.keyStoreEntryPasswords = keyStoreEntryPasswords;
    }
}
