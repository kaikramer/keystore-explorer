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
package org.kse.gui;

import java.awt.Container;
import java.awt.Dimension;
import java.awt.Image;
import java.awt.image.BufferedImage;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JSeparator;
import javax.swing.SwingConstants;

/**
 * Utilities for MiG Layout.
 */
public class MiGUtil {

    private MiGUtil() {
    }

    /**
     * Adds a labeled horizontal separator to the specified container.
     *
     * @param container Container to add separator to
     * @param text      Separator label text
     */
    public static void addSeparator(Container container, String text) {
        JLabel l = new JLabel(text, SwingConstants.LEADING);

        container.add(l, "gapbottom 1, span, split 2, aligny center");
        container.add(new JSeparator(), "gapleft rel, growx, wrap unrel");
    }

    /**
     * Adds a vertical separator with some additional space to the left and right to the specified container.
     *
     * @param container Container to add separator to
     * @param visible   Whether the separator is visible
     */
    public static void addButtonSeparator(Container container, boolean visible) {
        container.add(createButtonSeparator(visible), "gapleft unrel, gapright unrel, hidemode 3");
    }

    /**
     * Creates a vertical separator for use between buttons.
     *
     * @param visible True if the button separator is visible.
     * @return Button separator
     */
    public static JSeparator createButtonSeparator(boolean visible) {
        JSeparator jSeparator = new JSeparator(SwingConstants.VERTICAL);
        jSeparator.setPreferredSize(new Dimension(3, 20));
        jSeparator.setVisible(visible);

        return jSeparator;
    }

    /**
     * Creates a spacer that is the same size as an 16x16 icon button. Each L&F creates
     * buttons of differing sizes so this method uses a hidden 16x16 icon based button
     * spacer that works for all L&F.
     *
     * @return A spacer.
     */
    public static JButton createIconButtonSpacer() {
        Image image = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);
        JButton button = new JButton(new ImageIcon(image));
        button.setEnabled(false);
        button.setVisible(false);
        return button;
    }

}
