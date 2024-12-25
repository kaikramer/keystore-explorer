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
package org.kse.gui.password;

import javax.swing.JComponent;
import javax.swing.JPasswordField;

import org.kse.gui.preferences.PreferencesManager;
import org.kse.utilities.PRNG;

public class PasswordDialogHelper {
    private PasswordDialogHelper() {
    }

    /**
     * Prefills the password fields with a generated password.
     * <p>
     * The generated password is based on the current password generator settings.
     * </p>
     *
     * @param jpfFirst   the first password field
     * @param jpfConfirm the second password field
     */
    public static void preFillPasswordFields(JComponent jpfFirst, JPasswordField jpfConfirm) {
        var generatorSettings = PreferencesManager.getPreferences().getPasswordGeneratorSettings();
        char[] generatedPassword = PRNG.generatePassword(generatorSettings);
        if (jpfFirst instanceof JPasswordQualityField) {
            ((JPasswordQualityField) jpfFirst).setPassword(generatedPassword);
        } else {
            ((JPasswordField) jpfFirst).setText(new String(generatedPassword));
        }
        jpfConfirm.setText(new String(generatedPassword));
    }

    /**
     * Creates a password input field with a quality indicator based on the current password quality settings
     * (or a normal one if password quality indicator is disabled in the settings).
     *
     * @return the password input field
     */
    public static JComponent createPasswordInputField(PasswordQualityConfig passwordQualityConfig) {
        if (passwordQualityConfig.getEnabled()) {
            if (passwordQualityConfig.getEnforced()) {
                return new JPasswordQualityField(15, passwordQualityConfig.getMinimumQuality());
            } else {
                return new JPasswordQualityField(15);
            }
        } else {
            JPasswordField jPasswordField = new JPasswordField(15);
            jPasswordField.putClientProperty("JPasswordField.cutCopyAllowed", true);
            return jPasswordField;
        }
    }


}
