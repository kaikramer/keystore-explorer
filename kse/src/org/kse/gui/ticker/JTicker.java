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
package org.kse.gui.ticker;

import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.CellRendererPane;
import javax.swing.JComponent;
import javax.swing.Timer;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;

/**
 * Ticker Swing control to display scolling (right to left) text items.
 *
 */
public class JTicker extends JComponent implements ActionListener, ListDataListener {
	private static final long serialVersionUID = 1L;

	/** Renderer to display ticker */
	protected TickerRenderer renderer;

	/** Model to hold ticker items */
	protected TickerModel model;

	/** Interval between item movement in msecs */
	protected int interval = 40;

	/** Movement of items in pixels */
	protected int increment = 2;

	/** Gap between items in pixels */
	protected int gap = 20;

	/** Used in painting */
	protected CellRendererPane renderPane = new CellRendererPane();

	/** Records the positions of the ticker's items */
	protected int[] positions;

	/** Start offset in pixels */
	protected int offset;

	/** Timer that drives the ticking */
	protected Timer timer;

	/**
	 * Construct a JTicker using the default model and renderer.
	 */
	public JTicker() {
		this(new DefaultTickerModel());
	}

	/**
	 * Construct a JTicker using the supplied model and default renderer.
	 *
	 * @param model
	 *            The model
	 */
	public JTicker(TickerModel model) {
		this(model, new DefaultTickerRenderer());
	}

	/**
	 * Construct a JTicker using the supplied model and renderer.
	 *
	 * @param model
	 *            The model
	 * @param renderer
	 *            the renderer
	 */
	public JTicker(TickerModel model, TickerRenderer renderer) {
		setRenderer(renderer);
		setModel(model);
	}

	/**
	 * Start the ticker - do this only after the GUI has been packed as the
	 * offset needs to know the actual width of the control to set itself
	 * correctly.
	 */
	public void start() {
		// Calculate poitions of items
		calculatePositionArray();

		// Set controls preferred size (gets height correct)
		setPreferredSize(calculatePreferredSize());

		/*
		 * Set initial offset to width of ticker (hence ensuring first item
		 * appears out of the far right with no wait)
		 */
		offset = getWidth();

		// Create and start timer to get items moving
		timer = new Timer(interval, this);
		timer.start();
	}

	/**
	 * Stop the ticker - do this before the parent is destroyed.
	 *
	 */
	public void stop() {
		timer.stop();
	}

	/**
	 * Add an item to the ticker.
	 *
	 * @param item
	 *            Item to add
	 */
	public void addItem(Object item) {
		model.add(item);
	}

	/**
	 * Remove an item to the ticker.
	 *
	 * @param item
	 *            Item to remove
	 */
	public void removeItem(Object item) {
		model.remove(item);
	}

	/**
	 * Set gap between items.
	 *
	 * @param gap
	 *            Gap (pixels)
	 */
	public void setGap(int gap) {
		this.gap = gap;
	}

	/**
	 * Get gap between items.
	 *
	 * @return Gap (pixels)
	 */
	public int getGap() {
		return gap;
	}

	/**
	 * Set item movement increment.
	 *
	 * @param increment
	 *            Increment (pixels)
	 */
	public void setIncrement(int increment) {
		this.increment = increment;
	}

	/**
	 * Get item movement increment.
	 *
	 * @return Increment (pixels)
	 */
	public int getIncrement() {
		return increment;
	}

	/**
	 * Set item movement interval.
	 *
	 * @param interval
	 *            Intervals (msecs)
	 */
	public void setInterval(int interval) {
		this.interval = interval;
	}

	/**
	 * Get item movement interval.
	 *
	 * @return Intervals (msecs)
	 */
	public int getInterval() {
		return interval;
	}

	/**
	 * Set JTicker's renderer.
	 *
	 * @param renderer
	 *            Renderer
	 */
	public void setRenderer(TickerRenderer renderer) {
		this.renderer = renderer;
		calculatePositionArray();
	}

	/**
	 * Get JTicker's renderer.
	 *
	 * @return renderer Renderer
	 */
	public TickerRenderer getRenderer() {
		return renderer;
	}

	/**
	 * Set JTicker's model.
	 *
	 * @param model
	 *            model
	 */
	public void setModel(TickerModel model) {
		if (model != null) {
			model.removeListDataListener(this);
		}

		this.model = model;
		model.addListDataListener(this);
		calculatePositionArray();
	}

	/**
	 * Get JTicker's model.
	 *
	 * @return model Model
	 */
	public TickerModel getModel() {
		return model;
	}

	/**
	 * Triggered by the timer firing. Update item positions and repaint ticker.
	 *
	 * @param event
	 *            Action event
	 */
	@Override
	public void actionPerformed(ActionEvent event) {
		// Decrement initial offset
		offset -= increment;
		int last = positions.length - 1;
		int min = -positions[last];

		if (offset < min) {
			offset = 0;
		}

		repaint();
	}

	/**
	 * Listen for items being added to the model.
	 *
	 * @param event
	 *            Event
	 */
	@Override
	public void intervalAdded(ListDataEvent event) {
		calculatePositionArray();
		setPreferredSize(calculatePreferredSize());
	}

	/**
	 * Listen for items being removed from the model.
	 *
	 * @param event
	 *            Event
	 */
	@Override
	public void intervalRemoved(ListDataEvent event) {
		calculatePositionArray();
		setPreferredSize(calculatePreferredSize());
	}

	/**
	 * Listen for a change to the items in the model.
	 *
	 * @param event
	 *            Event
	 */
	@Override
	public void contentsChanged(ListDataEvent event) {
		calculatePositionArray();
		setPreferredSize(calculatePreferredSize());
	}

	/**
	 * Calculate the positions of each of the items.
	 */
	protected void calculatePositionArray() {
		if (model == null) {
			return;
		}

		int pos = 0;
		int items = model.getSize();
		positions = new int[items + 1];
		positions[0] = 0;

		for (int i = 0; i < items; i++) {
			Object value = model.getElementAt(i);
			JComponent component = renderer.getTickerRendererComponent(this, value);
			Dimension size = component.getPreferredSize();
			pos += size.width + gap;
			positions[i + 1] = pos;
		}
	}

	/**
	 * Calculate the preferred size of the ticker based on its items.
	 *
	 * @return Preferred size
	 */
	protected Dimension calculatePreferredSize() {
		int width = (int) getPreferredSize().getWidth();
		int height = 0;
		int items = model.getSize();

		for (int i = 0; i < items; i++) {
			Object value = model.get(i);
			JComponent component = renderer.getTickerRendererComponent(this, value);
			Dimension cell = component.getPreferredSize();
			height = Math.max(height, (int) cell.getHeight());
		}

		Insets insets = getInsets();
		return new Dimension((width + insets.left + insets.right), (height + insets.top + insets.bottom));
	}

	/**
	 * Paint the JTicker.
	 *
	 * @param graphics
	 *            Graphics object used to draw JTicker
	 */
	@Override
	protected void paintComponent(Graphics graphics) {
		int width = getSize().width;
		int height = getSize().height;

		Insets insets = getInsets();

		graphics.setColor(getBackground());
		graphics.fillRect(insets.left, insets.top, width - (insets.left + insets.right), height
				- (insets.top + insets.bottom));

		int items = model.getSize();
		int right = positions[positions.length - 1];

		for (int i = 0; i < items * 2; i++) {
			int index = (i < items) ? i : i - items;
			int adjust = insets.left + offset;
			int head = positions[index] + adjust;
			int tail = positions[index + 1] + adjust;

			if (i >= items) {
				head += right;
				tail += right;
			}

			if ((head < width) && (tail > 0)) {
				Object value = model.getElementAt(index);
				JComponent component = renderer.getTickerRendererComponent(this, value);

				Dimension size = component.getPreferredSize();
				renderPane.paintComponent(graphics, component, this, head, insets.top, size.width, size.height);
			}
		}
	}
}
