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
package org.kse.gui.quickstart;

import java.awt.Color;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;

import javax.swing.JPanel;

import org.kse.gui.LnfUtil;

/**
 * JPanel with gradient.
 */
public class JGradientPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    private Color lightColor1;
    private Color lightColor2;
    private Color darkColor1;
    private Color darkColor2;

    /**
     * Construct a Gradient panel using the supplied colours.
     *
     * @param lightColor1 First light colour
     * @param lightColor2 Second light colour
     * @param darkColor1 First dark colour
     * @param darkColor2 Second dark colour
     */
    public JGradientPanel(Color lightColor1, Color lightColor2, Color darkColor1, Color darkColor2) {
        this.lightColor1 = lightColor1;
        this.lightColor2 = lightColor2;
        this.darkColor1 = darkColor1;
        this.darkColor2 = darkColor2;
    }

    /**
     * Paint component with gradient.
     *
     * @param g The graphics object on which to paint
     */
    @Override
    public void paintComponent(Graphics g) {
        Graphics2D g2d = (Graphics2D) g;
        Color color1 = LnfUtil.isDarkLnf() ? darkColor1 : lightColor1;
        Color color2 = LnfUtil.isDarkLnf() ? darkColor2 : lightColor2;
        GradientPaint gradient = new GradientPaint(0, 0, color1, getWidth(), getHeight(), color2);
        g2d.setPaint(gradient);
        g.fillRect(0, 0, this.getWidth(), this.getHeight());
    }
}
