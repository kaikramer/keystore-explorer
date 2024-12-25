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
package org.kse.gui.preferences.data;

/**
 * Config bean for the password generator settings.
 */
public class PasswordGeneratorSettings {
    public static final int PWD_GEN_MIN_LENGTH = 4;
    public static final int PWD_GEN_MAX_LENGTH = 50;

    private boolean enabled = true;
    private boolean includeLowerCaseLetters = true;
    private boolean includeUpperCaseLetters = true;
    private boolean includeDigits = true;
    private boolean includeSpecialCharacters = true;
    private int length = 20;

    public PasswordGeneratorSettings() {
    }

    public PasswordGeneratorSettings(boolean enabled, boolean includeLowerCaseLetters, boolean includeUpperCaseLetters,
                                     boolean includeDigits, boolean includeSpecialCharacters, int length) {
        this.enabled = enabled;
        this.includeLowerCaseLetters = includeLowerCaseLetters;
        this.includeUpperCaseLetters = includeUpperCaseLetters;
        this.includeDigits = includeDigits;
        this.includeSpecialCharacters = includeSpecialCharacters;
        this.length = length;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isIncludeLowerCaseLetters() {
        return includeLowerCaseLetters;
    }

    public void setIncludeLowerCaseLetters(boolean includeLowerCaseLetters) {
        this.includeLowerCaseLetters = includeLowerCaseLetters;
    }

    public boolean isIncludeUpperCaseLetters() {
        return includeUpperCaseLetters;
    }

    public void setIncludeUpperCaseLetters(boolean includeUpperCaseLetters) {
        this.includeUpperCaseLetters = includeUpperCaseLetters;
    }

    public boolean isIncludeDigits() {
        return includeDigits;
    }

    public void setIncludeDigits(boolean includeDigits) {
        this.includeDigits = includeDigits;
    }

    public boolean isIncludeSpecialCharacters() {
        return includeSpecialCharacters;
    }

    public void setIncludeSpecialCharacters(boolean includeSpecialCharacters) {
        this.includeSpecialCharacters = includeSpecialCharacters;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }
}
