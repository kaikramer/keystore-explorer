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
package org.kse.gui.components;

import javax.swing.JTextArea;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

/**
 * Basically a JTextArea that looks like a JLabel and can be used for long labels that span multiple lines.
 */
public class JMultiLineLabel extends JTextArea {
    private static final long serialVersionUID = 1L;

    /**
     * c-tor
     * @param text Text that is displayed, use \n for line breaks
     */
    public JMultiLineLabel(String text) {
        super(text);
        setEditable(false);
        setLineWrap(true);
        setWrapStyleWord(true);
        setFocusable(false);
        setFont(UIManager.getFont("Label.font"));
        setOpaque(false);
        setBorder(new EmptyBorder(0, 0, 0, 0));
    }
}
