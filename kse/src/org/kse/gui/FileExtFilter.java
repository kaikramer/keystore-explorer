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
package org.kse.gui;

import java.io.File;

import javax.swing.filechooser.FileFilter;

/**
 * File filter specifically for filtering against file extensions.
 *
 */
public class FileExtFilter extends FileFilter {
	private String[] exts;
	private String description;

	/**
	 * Construct a FileExtFilter for a single file extension.
	 *
	 * @param ext
	 *            The file extension (eg "exe" for a Windows executable)
	 * @param description
	 *            Short description of the file extension
	 */
	public FileExtFilter(String ext, String description) {
		exts = new String[1];
		exts[0] = ext;
		this.description = description;
	}

	/**
	 * Construct a FileExtFilter for a set of related file extension.
	 *
	 * @param exts
	 *            The file extension (eg "exe" for a Windows executable)
	 * @param description
	 *            Short collective description for the file extensions
	 */
	public FileExtFilter(String[] exts, String description) {
		this.exts = new String[exts.length];

		System.arraycopy(exts, 0, this.exts, 0, exts.length);

		this.description = description;
	}

	/**
	 * Does the supplied file match the filter?
	 *
	 * @param file
	 *            The file to filter
	 * @return True if the file matches the filter, false otherwise
	 */
	@Override
	public boolean accept(File file) {
		if (file.isDirectory()) {
			return true;
		}

		String fileExt = getExtension(file);

		if (fileExt == null) {
			return false;
		}

		for (int i = 0; i < exts.length; i++) {
			String ext = exts[i];

			if (fileExt.equalsIgnoreCase(ext)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get the description.
	 *
	 * @return The description
	 */
	@Override
	public String getDescription() {
		return description;
	}

	public String[] getExtensions() {
		return exts;
	}

	private String getExtension(File file) {
		String ext = null;
		String name = file.getName();
		int i = name.lastIndexOf('.');

		if (i > -1 && i < name.length() - 1) {
			ext = name.substring(i + 1).toLowerCase();
		}
		return ext;
	}
}
