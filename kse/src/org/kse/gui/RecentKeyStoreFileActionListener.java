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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JOptionPane;

import org.kse.gui.actions.OpenAction;

/**
 * ActionListener intended for use with the JMenuItemRecentFile class. The
 * ActionListener is used to open a KeyStore file from the menu item.
 *
 */
public class RecentKeyStoreFileActionListener implements ActionListener {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");
	private File recentFile;
	private KseFrame kseFrame;

	/**
	 * Create an RecentKeyStoreFileActionListener for the supplied KeyStore file
	 * and KseFrame.
	 *
	 * @param recentFile
	 *            Recent KeyStore file
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public RecentKeyStoreFileActionListener(File recentFile, KseFrame kseFrame) {
		this.recentFile = recentFile;
		this.kseFrame = kseFrame;
	}

	/**
	 * Action to perform to open the KeyStore file in response to an
	 * ActionEvent.
	 *
	 * @param evt
	 *            Action event
	 */
	@Override
	public void actionPerformed(ActionEvent evt) {
		kseFrame.setDefaultStatusBarText();

		if (!recentFile.isFile()) {
			// File does not exist - invalidate it to remove it from the recent
			// files menu
			JMenuItemRecentFile jmiRecentFile = (JMenuItemRecentFile) evt.getSource();
			JMenuRecentFiles jmRecentFiles = jmiRecentFile.getRecentFilesMenu();
			jmRecentFiles.invalidate(jmiRecentFile);

			JOptionPane
			.showMessageDialog(kseFrame.getUnderlyingFrame(), MessageFormat.format(
					res.getString("RecentKeyStoreFileActionListener.NotFile.message"), recentFile), res
					.getString("RecentKeyStoreFileActionListener.OpenKeyStore.Title"),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		OpenAction openAction = new OpenAction(kseFrame);
		openAction.openKeyStore(recentFile);
	}
}
