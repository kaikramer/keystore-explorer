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
package org.kse.utilities.rng;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.kse.gui.preferences.data.PasswordGeneratorSettings;

/**
 * Password generator for purposes where no special requirements have to be met.
 * <p>
 * Seeded once per application run.
 */
public final class PasswordGenerator {
    public static final String LOWER_CASE_LETTERS = "abcdefghijklmnopqrstuvwxyz";
    public static final String UPPER_CASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String DIGITS = "0123456789";
    public static final String SPECIAL_CHARACTERS = "+-,.;:!#()[]{}<>|/@%=^";

    private static final SecureRandom random = RNG.newInstanceDefault();

    private PasswordGenerator(){
    }

    /**
     * Creates a random password according to the given settings.
     *
     * @param generatorSettings Settings for the password generator
     * @return The generated password
     */
    public static char[] generatePassword(PasswordGeneratorSettings generatorSettings) {
        // make sure that at least one character from every configured category is in the generated password
        StringBuilder password = new StringBuilder();
        String combinedChars = "";
        if (generatorSettings.isIncludeLowerCaseLetters()) {
            combinedChars += LOWER_CASE_LETTERS;
            password.append(LOWER_CASE_LETTERS.charAt(random.nextInt(LOWER_CASE_LETTERS.length())));
        }
        if (generatorSettings.isIncludeUpperCaseLetters()) {
            combinedChars += UPPER_CASE_LETTERS;
            password.append(UPPER_CASE_LETTERS.charAt(random.nextInt(UPPER_CASE_LETTERS.length())));
        }
        if (generatorSettings.isIncludeDigits()) {
            combinedChars += DIGITS;
            password.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        }
        if (generatorSettings.isIncludeSpecialCharacters()) {
            combinedChars += SPECIAL_CHARACTERS;
            password.append(SPECIAL_CHARACTERS.charAt(random.nextInt(SPECIAL_CHARACTERS.length())));
        }

        for (int i = password.length(); i < generatorSettings.getLength(); i++) {
            password.append(combinedChars.charAt(random.nextInt(combinedChars.length())));
        }

        return shuffleString(password.toString());
    }

    private static char[] shuffleString(String input) {
        List<Character> characters = new ArrayList<>();
        for (char c : input.toCharArray()) {
            characters.add(c);
        }
        StringBuilder output = new StringBuilder(input.length());
        while (!characters.isEmpty()) {
            output.append(characters.remove(random.nextInt(characters.size())));
        }
        return output.toString().toCharArray();
    }

}
