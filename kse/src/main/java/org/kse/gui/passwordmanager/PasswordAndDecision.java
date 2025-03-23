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

/**
 * Class to hold a password and a decision on whether to save it or not.
 */
public class PasswordAndDecision {
    private Password password;
    private boolean savePassword;

    /**
     * Construct a PasswordAndDecision object.
     *
     * @param password      The password
     * @param savePassword  Whether to save the password
     */
    public PasswordAndDecision(Password password, boolean savePassword) {
        this.password = password;
        this.savePassword = savePassword;
    }

    /**
     * Get the password.
     *
     * @return The password
     */
    public Password getPassword() {
        return password;
    }

    /**
     * Check if the password should be saved.
     *
     * @return True if the password should be saved, false otherwise
     */
    public boolean isSavePassword() {
        return savePassword;
    }
}
