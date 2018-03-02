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
package org.kse.gui.dnd;

import java.text.MessageFormat;

import javax.swing.ImageIcon;

/**
 * Abstract base class for all draggable KeyStore entries.
 *
 */
public abstract class DragEntry {
	private String name;

	/**
	 * Construct drag entry.
	 *
	 * @param name
	 *            Entry name
	 */
	public DragEntry(String name) {
		this.name = name;
	}

	/**
	 * Get entry name.
	 *
	 * @return Entry name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get file name for entry. File created on drag's drop.
	 *
	 * @return File name - "entry_name.extension".
	 */
	public String getFileName() {
		return MessageFormat.format("{0}.{1}", getName(), getExtension());
	}

	/**
	 * Get entry image - to display while dragging.
	 *
	 * @return Entry image
	 */
	public abstract ImageIcon getImage();

	/**
	 * Get entry file extension. Used to generate file name.
	 *
	 * @return File extension
	 */
	public abstract String getExtension();

	/**
	 * Get entry content as binary. Product of dragging in file.
	 *
	 * @return Content
	 */
	public abstract byte[] getContent();

	/**
	 * Get entry content as a string.
	 *
	 * @return Content
	 */
	public abstract String getContentString();
}
