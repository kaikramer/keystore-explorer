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
import java.util.Properties;

/**
 * Simple class intended to store the current directory for a file centric GUI
 * application. Wraps the "user.dir" System property.
 *
 */
public class CurrentDirectory {
	static {
		initialiseWorkingDirToBeHomeDir();
	}

	private CurrentDirectory() {
	}

	private static void initialiseWorkingDirToBeHomeDir() {
		String homeDir = System.getProperty("user.home");

		if (homeDir != null) {
			System.setProperty("user.dir", homeDir);
		}
	}

	/**
	 * Update CurrentSirectory to be the supplied directory.
	 *
	 * @param directory
	 *            Used to set current directory
	 */
	public static void update(File directory) {
		if (directory != null && directory.exists()) {
			Properties sysProps = new Properties(System.getProperties());
			sysProps.setProperty("user.dir", directory.getAbsolutePath());
			System.setProperties(sysProps);
		}
	}

	/**
	 * Update CurrentDirectory based on the supplied file. If the file exists
	 * then its parent is used.
	 *
	 * @param file
	 *            Used to set current directory
	 */
	public static void updateForFile(File file) {
		if (file != null) {
			File directory = file.getParentFile();

			update(directory);
		}
	}

	/**
	 * Get the current directory.
	 *
	 * @return Current directory
	 */
	public static File get() {
		return new File(System.getProperty("user.dir"));
	}
}
