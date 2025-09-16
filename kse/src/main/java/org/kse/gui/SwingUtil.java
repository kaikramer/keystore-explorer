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
 *
 */

package org.kse.gui;

import java.awt.FontMetrics;

import javax.swing.JLabel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;

public class SwingUtil {
    private SwingUtil() {
    }

    /**
     * Fix scrolling in a JScrollPane. This method sets the unit increment of the vertical and horizontal scroll bars to
     * the height of a line and the width of a character, respectively. This makes scrolling faster and more responsive.
     * <p>
     * Without this fix, scrolling is slow because the unit increment is set to a fixed value that is too small.
     * <p>
     * Before calling this method, the JScrollPane should be populated with content.
     * </p>
     *
     * @param jScrollPane Scroll pane to fix
     */
    public static void fixScrolling(JScrollPane jScrollPane) {
        JLabel systemLabel = new JLabel();
        FontMetrics metrics = systemLabel.getFontMetrics(systemLabel.getFont());
        int lineHeight = metrics.getHeight();
        int charWidth = metrics.getMaxAdvance();

        JScrollBar systemVBar = new JScrollBar(JScrollBar.VERTICAL);
        JScrollBar systemHBar = new JScrollBar(JScrollBar.HORIZONTAL);
        int verticalIncrement = systemVBar.getUnitIncrement();
        int horizontalIncrement = systemHBar.getUnitIncrement();

        jScrollPane.getVerticalScrollBar().setUnitIncrement(lineHeight * verticalIncrement);
        jScrollPane.getHorizontalScrollBar().setUnitIncrement(charWidth * horizontalIncrement);
    }
}