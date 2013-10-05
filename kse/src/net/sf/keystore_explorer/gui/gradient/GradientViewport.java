/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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
package net.sf.keystore_explorer.gui.gradient;

import java.awt.Color;
import java.awt.Graphics;

import javax.swing.JViewport;

/**
 * An extension of javax.swing.JViewport that allows gradient painting of its
 * background.
 * <p />
 * It is important to remember to set the opacity of the component that this
 * viewport displays to false, so that the viewport's background can show
 * through.
 * 
 */
public class GradientViewport extends JViewport {
	private GradientPainter gp;

	/**
	 * Creates a GradientViewport with the specified gradient painter.
	 * 
	 * @param gp
	 *            The gradient painter
	 */
	public GradientViewport(GradientPainter gp) {
		setGradientPainter(gp);
		gp.setComponent(this);
		setBackground(Color.WHITE);
	}

	/**
	 * Overriding paintComponent allows us to paint the gradient on the
	 * background.
	 * 
	 * @param g
	 *            The graphics object on which to paint
	 */
	public void paintComponent(Graphics g) {
		super.paintComponent(g);

		if (gp != null) {
			gp.paint(g);
		}
	}

	/**
	 * Set the gradient painter.
	 * 
	 * @param gp
	 *            The gradient painter
	 */
	public void setGradientPainter(GradientPainter gp) {
		this.gp = gp;
		gp.setComponent(this);
		repaint();
	}

	/**
	 * Return gradient painter.
	 * 
	 * @return The gradient painter
	 */
	public GradientPainter getGradientPainter() {
		return gp;
	}
}
