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
package org.kse.gui.preferences;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

import javax.swing.JButton;
import javax.swing.JPasswordField;

/**
 * Special JButton to copy the content of an associated password field.
 */
public class JCopyPasswordButton extends JButton {
    private final JPasswordField passwordField;

    /**
     * Constructor.
     * @param passwordField the associated password field for the copy operation
     */
    public JCopyPasswordButton(JPasswordField passwordField) {
        super("Copy");
        this.passwordField = passwordField;
        initializeButtonBehavior();
    }

    private void initializeButtonBehavior() {
        this.addActionListener(e -> {
            StringSelection stringSelection = new StringSelection(new String(passwordField.getPassword()));
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
        });
    }
}

