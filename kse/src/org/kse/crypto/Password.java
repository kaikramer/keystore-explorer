/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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
package org.kse.crypto;

import java.util.ResourceBundle;

/**
 * Wraps a character array based password providing the ability to null the
 * password to remove it from memory for security.
 */
public class Password {
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/resources");
    private char[] wrappedPassword;
    private boolean nulled;

    /**
     * Construct password wrapper.
     *
     * @param password Password to wrap
     */
    public Password(char[] password) {
        this.wrappedPassword = password;
        nulled = false; // Initially not nulled
    }

    /**
     * Copy construct password wrapper.
     *
     * @param password Password wrapper to copy
     */
    public Password(Password password) {
        if (password.isNulled()) {
            nulled = true;
            wrappedPassword = new char[] { 0 };
        } else {
            char[] wrappedPwd = password.toCharArray();
            if (wrappedPwd != null) {
                this.wrappedPassword = new char[wrappedPwd.length];
                System.arraycopy(wrappedPwd, 0, this.wrappedPassword, 0, this.wrappedPassword.length);
            }
        }
    }

    /**
     * Get wrapped password as a char array.
     *
     * @return Wrapped password
     * @throws IllegalStateException If password requested after it has been nulled
     */
    public char[] toCharArray() throws IllegalStateException {
        if (nulled) {
            throw new IllegalStateException(res.getString("NoGetPasswordNulled.message"));
        }

        return wrappedPassword;
    }

    /**
     * Get wrapped password as a byte array.
     *
     * @return Wrapped password
     * @throws IllegalStateException If password requested after it has been nulled
     */
    public byte[] toByteArray() throws IllegalStateException {
        if (nulled) {
            throw new IllegalStateException(res.getString("NoGetPasswordNulled.message"));
        }

        if (wrappedPassword == null) {
            return null;
        }

        byte[] passwordBytes = new byte[wrappedPassword.length];

        for (int i = 0; i < wrappedPassword.length; i++) {
            passwordBytes[i] = (byte) wrappedPassword[i];
        }

        return passwordBytes;
    }

    /**
     * Null the wrapped password.
     */
    public void nullPassword() {
        if (wrappedPassword == null) {
            return;
        }
        for (int i = 0; i < wrappedPassword.length; i++) {
            wrappedPassword[i] = 0;
        }
        nulled = true;
    }

    /**
     * Has the wrapped password been nulled?
     *
     * @return True if it has
     */
    public boolean isNulled() {
        return nulled;
    }

    /**
     * Is the password an empty string?
     *
     * @return True if it is
     */
    public boolean isEmpty() {
        return wrappedPassword.length == 0;
    }

    /**
     * Is the supplied object equal to the password wrapper, i.e. do they wrap the
     * same password.
     *
     * @param object Object to check
     * @return True if the object is equal
     */
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }

        if (!(object instanceof Password)) {
            return false;
        }

        Password password = (Password) object;

        if (password.wrappedPassword == null) {
            return wrappedPassword == null;
        }

        if (wrappedPassword.length != password.wrappedPassword.length) {
            return false;
        }

        for (int i = 0; i < wrappedPassword.length; i++) {
            if (wrappedPassword[i] != password.wrappedPassword[i]) {
                return false;
            }
        }

        return true;
    }

    /**
     * Nulls the password. Just a fail-safe, applications should null the
     * password programmatically.
     */
    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        nullPassword();
    }
}
