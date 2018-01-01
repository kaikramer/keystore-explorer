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
package org.kse.gui.statusbar;

import javax.swing.JMenuItem;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.kse.utilities.os.OperatingSystem;

/**
 * Handles change events on a menu item that causes the status bar text to show
 * or hide help text for the menu item.
 *
 */
public class StatusBarChangeHandler implements ChangeListener {
	private JMenuItem jmi;
	private String helpText;
	private StatusBar statusBar;

	/**
	 * Construct a StatusBarChangeHandler.
	 *
	 * @param jmi
	 *            The menu item
	 * @param helpText
	 *            Help text for the menu item
	 * @param statusBar
	 *            The status bar
	 */
	public StatusBarChangeHandler(JMenuItem jmi, String helpText, StatusBar statusBar) {
		this.jmi = jmi;
		this.helpText = helpText;
		this.statusBar = statusBar;
		jmi.addChangeListener(this);
	}

	/**
	 * Menu item's state has changed - if armed show its help text, otherwise
	 * hide any help text.
	 *
	 * @param evt
	 *            The change event
	 */
	@Override
	public void stateChanged(ChangeEvent evt) {
		/*
		 * Only bother if not using Mac OS - on there stateChagned is not fired
		 * for the application manu bar's items so for consistency we will fire
		 * it at all
		 */
		if (!OperatingSystem.isMacOs()) {
			if (jmi.isArmed()) {
				// Display help text
				statusBar.setStatusBarText(helpText);
			} else {
				// Display default status
				statusBar.setDefaultStatusBarText();
			}
		}
	}
}
