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
import java.util.ArrayList;

import javax.swing.JMenu;

/**
 * Menu with Recent File List capability, ie a list of files where the most
 * recently accessed file is set as the first item shifting other files down and
 * the list contains no duplicates.
 *
 */
public class JMenuRecentFiles extends JMenu {
	private static final long serialVersionUID = 1L;
	private JMenuItemRecentFile[] jmiRecentFiles;
	private static final int MAX_LENGTH = 9;

	/**
	 * Construct a JMenuRecentFiles.
	 *
	 * @param title
	 *            Title of menu
	 * @param length
	 *            Length of recent files list to maintain
	 */
	public JMenuRecentFiles(String title, int length) {
		super(title);

		if (length > MAX_LENGTH) {
			length = MAX_LENGTH;
		}

		jmiRecentFiles = new JMenuItemRecentFile[length];
	}

	private void removeAllRecentFiles() {
		for (int i = 0; i < jmiRecentFiles.length; i++) {
			if (jmiRecentFiles[i] == null) {
				break;
			}

			remove(jmiRecentFiles[i]);
		}
	}

	private void addAllRecentFiles() {
		for (int i = 0; i < jmiRecentFiles.length; i++) {
			if (jmiRecentFiles[i] == null) {
				break;
			}
			add(jmiRecentFiles[i], i);
		}
	}

	private int findRecentFile(File recentFile) {
		int index = -1;

		for (int i = 0; i < jmiRecentFiles.length; i++) {
			if (jmiRecentFiles[i] == null) {
				break;
			}

			if (recentFile.equals(jmiRecentFiles[i].getFile())) {
				index = i;
				break;
			}
		}

		return index;
	}

	/**
	 * Add a recent file menu item to the menu. Only call when the menu is
	 * completely populated with standard menu items and separators.
	 *
	 * @param jmirfNew
	 *            The new recent file menu item
	 */
	public void add(JMenuItemRecentFile jmirfNew) {
		int index = findRecentFile(jmirfNew.getFile());

		// Menu item already exists at first position
		if (index == 0) {
			return;
		}

		removeAllRecentFiles();

		jmirfNew.setPosition(1);

		// Item already exists outside of first position
		if (index != -1) {
			// Introduce it to the first position and move the others up over
			// its old position
			for (int i = 0; i <= index; i++) {
				JMenuItemRecentFile jmirfTmp = jmiRecentFiles[i];
				jmiRecentFiles[i] = jmirfNew;
				jmirfNew = jmirfTmp;
				jmirfNew.setPosition(i + 2);
			}
		}
		// Item does not exist in the menu
		else {
			// Introduce new item to the start of the list and shift the others
			// up one
			for (int i = 0; i < jmiRecentFiles.length; i++) {
				JMenuItemRecentFile jmirfTmp = jmiRecentFiles[i];
				jmiRecentFiles[i] = jmirfNew;
				jmirfNew = jmirfTmp;

				if (jmirfNew == null) {
					break; // Done shifting
				}
				jmirfNew.setPosition(i + 2);
			}
		}

		addAllRecentFiles();
	}

	/**
	 * Invalidate a recent file menu item by removing it from the menu. Call
	 * when a recent file no longer exists.
	 *
	 * @param jmirfOld
	 *            The recent file menu item to remove
	 */
	public void invalidate(JMenuItemRecentFile jmirfOld) {
		int index = findRecentFile(jmirfOld.getFile());

		if (index == -1) {
			return;
		}

		removeAllRecentFiles();

		for (int i = index; i < jmiRecentFiles.length; i++) {

			if (i < (jmiRecentFiles.length - 1)) {
				jmiRecentFiles[i] = jmiRecentFiles[i + 1];

				if (jmiRecentFiles[i + 1] != null) {
					jmiRecentFiles[i].setPosition(i + 1);
				}
			} else {
				jmiRecentFiles[i] = null;
			}
		}

		addAllRecentFiles();
	}

	/**
	 * Get the set of recent files currently maintained by the menu in order.
	 *
	 * @return The recent files
	 */
	public File[] getRecentFiles() {
		ArrayList<File> recentFiles = new ArrayList<File>();

		for (int i = 0; i < jmiRecentFiles.length; i++) {
			if (jmiRecentFiles[i] == null) {
				break;
			}

			recentFiles.add(jmiRecentFiles[i].getFile());
		}

		return recentFiles.toArray(new File[recentFiles.size()]);
	}
}
