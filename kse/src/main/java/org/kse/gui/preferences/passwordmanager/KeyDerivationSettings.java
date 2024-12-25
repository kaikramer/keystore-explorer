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

import java.util.Arrays;

import org.kse.gui.passwordmanager.KeyDerivationAlgorithm;

/**
 * Settings for deriving the key that is used for encrypting the passwords.
 */
public class KeyDerivationSettings {
    private KeyDerivationAlgorithm keyDerivationAlgorithm = KeyDerivationAlgorithm.PBKDF2;
    private byte[] salt;
    private int iterations;
    private int memLimitInMB;
    private int parallelism;
    private int derivedKeyLength;

    public KeyDerivationSettings() {}

    /**
     * Copy constructor
     * @param other settings to copy
     */
    public KeyDerivationSettings(KeyDerivationSettings other) {
        this.keyDerivationAlgorithm = other.keyDerivationAlgorithm;
        this.salt = other.salt != null ? Arrays.copyOf(other.salt, other.salt.length) : null;
        this.iterations = other.iterations;
        this.memLimitInMB = other.memLimitInMB;
        this.parallelism = other.parallelism;
        this.derivedKeyLength = other.derivedKeyLength;
    }

    // auto-generated getters/setters

    public KeyDerivationAlgorithm getKeyDerivationAlgorithm() {
        return keyDerivationAlgorithm;
    }

    public void setKeyDerivationAlgorithm(KeyDerivationAlgorithm keyDerivationAlgorithm) {
        this.keyDerivationAlgorithm = keyDerivationAlgorithm;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public int getIterations() {
        return iterations;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public int getDerivedKeyLength() {
        return derivedKeyLength;
    }

    public void setDerivedKeyLength(int derivedKeyLength) {
        this.derivedKeyLength = derivedKeyLength;
    }

    public int getMemLimitInMB() {
        return memLimitInMB;
    }

    public void setMemLimitInMB(int memLimitInMB) {
        this.memLimitInMB = memLimitInMB;
    }

    public int getParallelism() {
        return parallelism;
    }

    public void setParallelism(int parallelism) {
        this.parallelism = parallelism;
    }
}
