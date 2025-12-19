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

package org.kse.gui.preferences.data;

import org.kse.gui.passwordmanager.KeyDerivationAlgorithm;

/**
 * Config bean for storing settings for the password manager
 */
public class PasswordManagerSettings {
    private KeyDerivationAlgorithm keyDerivationAlgorithm = KeyDerivationAlgorithm.PBKDF2;
    private int iterations = 600_000;
    private int memLimitInMB = 64;

    public KeyDerivationAlgorithm getKeyDerivationAlgorithm() {
        return keyDerivationAlgorithm;
    }

    public void setKeyDerivationAlgorithm(KeyDerivationAlgorithm keyDerivationAlgorithm) {
        this.keyDerivationAlgorithm = keyDerivationAlgorithm;
    }

    public int getIterations() {
        return iterations;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public int getMemLimitInMB() {
        return memLimitInMB;
    }

    public void setMemLimitInMB(int memLimitInMB) {
        this.memLimitInMB = memLimitInMB;
    }
}
