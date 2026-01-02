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
package org.kse.gui.preferences.passwordmanager;

/**
 * Stores encrypted password and IV for one key entry
 */
public class KeyStoreEntryPassword {
    private String entryAlias;
    private byte[] encryptedKeyEntryPassword;
    private byte[] encryptedKeyEntryPasswordInitVector;

    // auto-generated getters/setters

    public String getEntryAlias() {
        return entryAlias;
    }

    public void setEntryAlias(String entryAlias) {
        this.entryAlias = entryAlias;
    }

    public byte[] getEncryptedKeyEntryPassword() {
        return encryptedKeyEntryPassword;
    }

    public void setEncryptedKeyEntryPassword(byte[] encryptedKeyEntryPassword) {
        this.encryptedKeyEntryPassword = encryptedKeyEntryPassword;
    }

    public byte[] getEncryptedKeyEntryPasswordInitVector() {
        return encryptedKeyEntryPasswordInitVector;
    }

    public void setEncryptedKeyEntryPasswordInitVector(byte[] encryptedKeyEntryPasswordInitVector) {
        this.encryptedKeyEntryPasswordInitVector = encryptedKeyEntryPasswordInitVector;
    }
}
