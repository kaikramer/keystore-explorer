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
package org.kse.utilities;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.kse.gui.preferences.data.PasswordGeneratorSettings;

public class PRNGTest {

    @Test
    public void testGeneratePasswordWithAllCharacterTypes() {
        PasswordGeneratorSettings settings = new PasswordGeneratorSettings(true, true, true, true, true, 20);
        char[] password = PRNG.generatePassword(settings);

        assertNotNull(password);
        assertEquals(20, password.length);

        boolean hasLowerCase = false;
        boolean hasUpperCase = false;
        boolean hasDigit = false;
        boolean hasSpecialChar = false;

        for (char c : password) {
            if (Character.isLowerCase(c)) hasLowerCase = true;
            if (Character.isUpperCase(c)) hasUpperCase = true;
            if (Character.isDigit(c)) hasDigit = true;
            if (PRNG.SPECIAL_CHARACTERS.indexOf(c) >= 0) hasSpecialChar = true;
        }

        assertTrue(hasLowerCase);
        assertTrue(hasUpperCase);
        assertTrue(hasDigit);
        assertTrue(hasSpecialChar);
    }

    @Test
    public void testGeneratePasswordWithOnlyLowerCase() {
        PasswordGeneratorSettings settings = new PasswordGeneratorSettings(true, true, false, false, false, 20);
        char[] password = PRNG.generatePassword(settings);

        assertNotNull(password);
        assertEquals(20, password.length);

        for (char c : password) {
            assertTrue(Character.isLowerCase(c));
        }
    }

    @Test
    public void testGeneratePasswordWithOnlyUpperCase() {
        PasswordGeneratorSettings settings = new PasswordGeneratorSettings(true, false, true, false, false, 20);
        char[] password = PRNG.generatePassword(settings);

        assertNotNull(password);
        assertEquals(20, password.length);

        for (char c : password) {
            assertTrue(Character.isUpperCase(c));
        }
    }

    @Test
    public void testGeneratePasswordWithOnlyDigits() {
        PasswordGeneratorSettings settings = new PasswordGeneratorSettings(true, false, false, true, false, 20);
        char[] password = PRNG.generatePassword(settings);

        assertNotNull(password);
        assertEquals(20, password.length);

        for (char c : password) {
            assertTrue(Character.isDigit(c));
        }
    }

    @Test
    public void testGeneratePasswordWithOnlySpecialCharacters() {
        PasswordGeneratorSettings settings = new PasswordGeneratorSettings(true, false, false, false, true, 20);
        char[] password = PRNG.generatePassword(settings);

        assertNotNull(password);
        assertEquals(20, password.length);

        for (char c : password) {
            assertTrue(PRNG.SPECIAL_CHARACTERS.indexOf(c) >= 0);
        }
    }

    @Test
    public void testGeneratePasswordWithMinLength() {
        PasswordGeneratorSettings settings = new PasswordGeneratorSettings(true, true, true, true, true,
                                                                           PasswordGeneratorSettings.PWD_GEN_MIN_LENGTH);
        char[] password = PRNG.generatePassword(settings);

        assertNotNull(password);
        assertEquals(PasswordGeneratorSettings.PWD_GEN_MIN_LENGTH, password.length);
    }

    @Test
    public void testGeneratePasswordWithMaxLength() {
        PasswordGeneratorSettings settings = new PasswordGeneratorSettings(true, true, true, true, true,
                                                                           PasswordGeneratorSettings.PWD_GEN_MAX_LENGTH);
        char[] password = PRNG.generatePassword(settings);

        assertNotNull(password);
        assertEquals(PasswordGeneratorSettings.PWD_GEN_MAX_LENGTH, password.length);
    }
}