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

package org.kse.gui.util;

import static java.awt.RenderingHints.KEY_FRACTIONALMETRICS;
import static java.awt.RenderingHints.KEY_TEXT_ANTIALIASING;
import static java.awt.RenderingHints.VALUE_FRACTIONALMETRICS_ON;
import static java.awt.RenderingHints.VALUE_TEXT_ANTIALIAS_ON;
import static java.awt.image.BufferedImage.TYPE_INT_ARGB;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontFormatException;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JLabel;

/**
 * Utility class for creating FontAwesome icons and labels.
 */
public class FontAwesomeIcon {
    private static final String FA_FONT_FILE = "Font Awesome 7 Free-Solid-900.otf";
    private static final Font fontAwesomeFont;

    static {
        try {
            InputStream is = FontAwesomeIcon.class.getResourceAsStream(FA_FONT_FILE);

            if (is == null) {
                throw new IOException("FontAwesome font file not found: " + FA_FONT_FILE);
            }

            fontAwesomeFont = Font.createFont(java.awt.Font.TRUETYPE_FONT, is);
        } catch (IOException | FontFormatException e) {
            // TODO Auto-generated catch block
            throw new RuntimeException(e);
        }
    }

    private FontAwesomeIcon() {
        // Prevent instantiation
    }

    /**
     * Creates a JLabel from a FontAwesome glyph.
     *
     * @param glyph FontAwesome glyph
     * @param size  Label size
     * @param color Label color
     * @return JLabel
     */
    public static JLabel getLabel(FontAwesomeGlyph glyph, float size, Color color) {
        JLabel label = new JLabel(Character.toString(glyph.getCodePoint()));
        label.setForeground(color);
        label.setFont(fontAwesomeFont.deriveFont(size));
        label.setSize(label.getPreferredSize().width + 1, label.getPreferredSize().height + 1);
        return label;
    }

    /**
     * Creates an Icon from a FontAwesome glyph.
     *
     * @param glyph FontAwesome glyph
     * @param size  Icon size
     * @param color Icon color
     * @return Icon
     */
    public static Icon getIcon(FontAwesomeGlyph glyph, float size, Color color) {
        JLabel label = getLabel(glyph, size, color);

        BufferedImage bufferedImage = new BufferedImage(label.getSize().width, label.getSize().height, TYPE_INT_ARGB);
        Graphics2D g2d = bufferedImage.createGraphics();
        g2d.setRenderingHint(KEY_TEXT_ANTIALIASING, VALUE_TEXT_ANTIALIAS_ON);
        g2d.setRenderingHint(KEY_FRACTIONALMETRICS, VALUE_FRACTIONALMETRICS_ON);
        label.print(g2d);
        g2d.dispose();

        return new ImageIcon(bufferedImage);
    }
}
