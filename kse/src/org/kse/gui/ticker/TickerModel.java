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

import javax.swing.ListModel;

/**
 * Interface for data models to use with the JTicker Swing control.
 *
 */
public interface TickerModel extends ListModel<Object> {
	/**
	 * Get the item in the model at the specified index.
	 *
	 * @param index
	 *            The index
	 * @return The item
	 */
	Object get(int index);

	/**
	 * Get the index in the model of the specified item.
	 *
	 * @param item
	 *            The item
	 * @return The index
	 */
	int indexOf(Object item);

	/**
	 * Add an item to the model.
	 *
	 * @param item
	 *            The item
	 */
	void add(Object item);

	/**
	 * Remove an item from the model.
	 *
	 * @param item
	 *            The item
	 */
	void remove(Object item);
}
