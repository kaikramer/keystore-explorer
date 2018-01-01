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

import java.awt.event.KeyEvent;
import java.io.File;

import javax.swing.JMenuItem;

/**
 * A recent file menu item. Used in recent file menus (JMenuRecentFiles) to open
 * files directly by activating a menu item either through normal means or the
 * mnemonic that reflects the menu items position in the list of recent files.
 * An action listener should be added to actually open the file. Other listeners
 * can be added as required to respond to other types of event.
 *
 */
public class JMenuItemRecentFile extends JMenuItem {
	private static final long serialVersionUID = 1L;
	private JMenuRecentFiles jmRecentFiles;
	private File recentFile;
	private int position;

	/**
	 * Construct a JMenuItemRecentFile.
	 *
	 * @param jmRecentFiles
	 *            Recent files menu
	 * @param recentFile
	 *            The recent file
	 */
	public JMenuItemRecentFile(JMenuRecentFiles jmRecentFiles, File recentFile) {
		super();

		this.jmRecentFiles = jmRecentFiles;
		this.recentFile = recentFile;
		setPosition(1);
	}

	/**
	 * Get the recent files menu.
	 *
	 * @return The recent files manu
	 */
	public JMenuRecentFiles getRecentFilesMenu() {
		return jmRecentFiles;
	}

	/**
	 * Get the recent file.
	 *
	 * @return The recent file
	 */
	public File getFile() {
		return recentFile;
	}

	/**
	 * Get the menu item's position in its recent file list (maintained by
	 * JMenuRecentFiles).
	 *
	 * @return Position
	 */
	public int getPosition() {
		return position;
	}

	void setPosition(int position) {
		this.position = position;
		setText((position) + " " + recentFile.getName());

		switch (position) {
		case 1:
			PlatformUtil.setMnemonic(this, KeyEvent.VK_1);
			break;
		case 2:
			PlatformUtil.setMnemonic(this, KeyEvent.VK_2);
			break;
		case 3:
			PlatformUtil.setMnemonic(this, KeyEvent.VK_3);
			break;
		case 4:
			PlatformUtil.setMnemonic(this, KeyEvent.VK_4);
			break;
		case 5:
			PlatformUtil.setMnemonic(this, KeyEvent.VK_5);
			break;
		case 6:
			PlatformUtil.setMnemonic(this, KeyEvent.VK_6);
			break;
		case 7:
			PlatformUtil.setMnemonic(this, KeyEvent.VK_7);
			break;
		case 8:
			PlatformUtil.setMnemonic(this, KeyEvent.VK_8);
			break;
		case 9:
			PlatformUtil.setMnemonic(this, KeyEvent.VK_9);
			break;
		}
	}
}
