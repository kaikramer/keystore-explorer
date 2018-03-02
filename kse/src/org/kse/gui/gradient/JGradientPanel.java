/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
package org.kse.gui.gradient;

import java.awt.Color;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;

import javax.swing.JPanel;

/**
 * JPanel with gradient.
 *
 */
public class JGradientPanel extends JPanel {
	private static final long serialVersionUID = 1L;
	private Color color1;
	private Color color2;

	/**
	 * Construct a Gradient panel using the supplied colours.
	 *
	 * @param color1
	 *            First colour
	 * @param color2
	 *            Second colour
	 */
	public JGradientPanel(Color color1, Color color2) {
		this.color1 = color1;
		this.color2 = color2;
	}

	/**
	 * Paint component with gradient.
	 *
	 * @param g
	 *            The graphics object on which to paint
	 */
	@Override
	public void paintComponent(Graphics g) {
		Graphics2D g2d = (Graphics2D) g;
		GradientPaint gradient = new GradientPaint(0, 0, color1, getWidth(), getHeight(), color2);
		g2d.setPaint(gradient);
		g.fillRect(0, 0, this.getWidth(), this.getHeight());
	}
}
