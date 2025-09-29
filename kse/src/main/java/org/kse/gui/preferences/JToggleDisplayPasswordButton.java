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
package org.kse.gui.preferences;

import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JPasswordField;

/**
 * Button to toggle the visibility of an associated password field.
 */
public class JToggleDisplayPasswordButton extends JButton {
    private static final long serialVersionUID = 3222235201966932207L;
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");
    private final JPasswordField passwordField;
    private boolean visible = false;

    /**
     * Constructor.
     * @param passwordField the password field to toggle the visibility of
     */
    public JToggleDisplayPasswordButton(JPasswordField passwordField) {
        super(res.getString("DPreferences.storedPasswords.jtdPasswordButton.show.text"));
        this.passwordField = passwordField;
        initializeButtonBehavior();
    }

    private void initializeButtonBehavior() {
        this.addActionListener(e -> {
            if (visible) {
                passwordField.setEchoChar('\u2022'); // Unicode Bullet
                setText(res.getString("DPreferences.storedPasswords.jtdPasswordButton.show.text"));
            } else {
                // show plain text
                passwordField.setEchoChar((char) 0);
                setText(res.getString("DPreferences.storedPasswords.jtdPasswordButton.hide.text"));
            }
            visible = !visible;
        });
    }
}

