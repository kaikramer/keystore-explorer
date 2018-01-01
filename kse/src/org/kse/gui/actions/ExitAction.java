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
package org.kse.gui.actions;

import java.awt.Toolkit;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.gui.CurrentDirectory;
import org.kse.gui.KseFrame;
import org.kse.gui.KseRestart;

/**
 * Action to exit.
 *
 */
public class ExitAction extends CloseAllAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExitAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_F4, InputEvent.ALT_MASK));
		putValue(LONG_DESCRIPTION, res.getString("ExitAction.statusbar"));
		putValue(NAME, res.getString("ExitAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExitAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ExitAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		exitApplication();
	}

	/**
	 * Exit the application.
	 */
	public void exitApplication() {
		exitApplication(false);
	}

	/**
	 * Exit the application and optionally restart.
	 *
	 * @param restart
	 *            Restart application if true
	 */
	public void exitApplication(boolean restart) {
		// Will any KeyStores be closed by exit?
		boolean keyStoresClosed = (kseFrame.getActiveKeyStoreHistory() != null);

		if (!closeAllKeyStores()) {
			return;
		}

		// Save dynamic application settings
		applicationSettings.setSizeAndPosition(kseFrame.getSizeAndPosition(keyStoresClosed));
		applicationSettings.setRecentFiles(kseFrame.getRecentFiles());
		applicationSettings.setCurrentDirectory(CurrentDirectory.get());
		applicationSettings.save();

		if (restart) {
			KseRestart.restart();
		}

		System.exit(0);
	}
}
