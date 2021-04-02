/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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
package org.kse.gui.statusbar;

/**
 * Interface for a status bar. Used with the StatusBarChangeHandler to support
 * the placing and removal of help messages into the status bar as menu items
 * are selected/de-selected.
 *
 */
public interface StatusBar {
	/**
	 * Display the supplied text in the status bar.
	 *
	 * @param status
	 *            Text to display
	 */
	void setStatusBarText(String status);

	/**
	 * Set the status bar text to its default message.
	 */
	void setDefaultStatusBarText();
}
