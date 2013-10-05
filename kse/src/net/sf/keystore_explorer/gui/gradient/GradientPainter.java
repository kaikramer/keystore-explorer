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
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Paint;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;

/**
 * Paints an entire component with a colour gradient.
 * 
 */
public class GradientPainter implements HierarchyListener {
	private GradientViewport paintComponent;
	private Color color1 = Color.WHITE;
	private Color color2 = new Color(128, 128, 255); // light blue

	/**
	 * Construct a Gradient painter using the default colours - white to light
	 * blue.
	 */
	public GradientPainter() {
	}

	/**
	 * Construct a Gradient painter using the supplied colours.
	 * 
	 * @param color1
	 *            First colour
	 * @param color2
	 *            Second colour
	 */
	public GradientPainter(Color color1, Color color2) {
		this.color1 = color1;
		this.color2 = color2;
	}

	/**
	 * Set first colour.
	 * 
	 * @param color1
	 *            First colour
	 */
	public void setColor1(Color color1) {
		this.color1 = color1;
	}

	/**
	 * Set second colour.
	 * 
	 * @param color2
	 *            Second colour
	 */
	public void setColor2(Color color2) {
		this.color2 = color2;
	}

	final void setComponent(GradientViewport component) {
		/*
		 * Called when this painter is registered with a viewport, to notify us
		 * of the component that we'll be painting on. This will replace the
		 * previous component if non-null
		 */

		if (paintComponent != null) {
			paintComponent.removeHierarchyListener(this);
			stop();
		}

		paintComponent = component;

		if (paintComponent != null) {
			if (paintComponent.isShowing()) {
				start();
			}
			paintComponent.addHierarchyListener(this);
		}
	}

	/**
	 * Return the viewport associated with this painter.
	 * 
	 * @return The viewport associated with this painter
	 */
	protected final GradientViewport getComponent() {
		return paintComponent;
	}

	/**
	 * Starts any animation that this painter might perform. This is called when
	 * this painter is registered with a new viewport, if the viewport's showing
	 * status is true. It will then be called every time that component's status
	 * changes to true.
	 */
	protected void start() {
	}

	/**
	 * Stops any animation that this painter might be performing. This is called
	 * when this painter is un-registered, or when the showing status of the
	 * current viewport changes to false.
	 */
	protected void stop() {
	}

	/**
	 * Paint gradient on component.
	 * 
	 * @param g
	 *            The graphics object on which to paint
	 */
	public void paint(Graphics g) {
		int width = getComponent().getWidth();
		int height = getComponent().getHeight();

		GradientPaint paint = new GradientPaint(0, 0, color1, width, height, color2, true);

		Graphics2D g2d = (Graphics2D) g;

		// Save the old paint
		Paint oldPaint = g2d.getPaint();

		// Set the paint to use for this operation
		g2d.setPaint(paint);

		// Fill the background using the gradient paint
		g2d.fillRect(0, 0, width, height);

		// Restore the original paint
		g2d.setPaint(oldPaint);
	}

	/**
	 * Listens for hierarchy events on the current viewport to start or stop
	 * this painter when the component's showing state changes.
	 * 
	 * @param evt
	 *            Hierarchy event
	 */
	public void hierarchyChanged(HierarchyEvent evt) {
		if ((evt.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != HierarchyEvent.SHOWING_CHANGED) {
			return;
		}

		if (paintComponent.isShowing()) {
			start();
		} else {
			stop();
		}
	}
}
