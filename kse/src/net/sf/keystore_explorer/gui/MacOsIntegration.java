/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2014 Kai Kramer
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
package net.sf.keystore_explorer.gui;

import java.io.File;

import net.sf.keystore_explorer.gui.actions.AboutAction;
import net.sf.keystore_explorer.gui.actions.ExitAction;
import net.sf.keystore_explorer.gui.actions.OpenAction;
import net.sf.keystore_explorer.gui.actions.PreferencesAction;

import com.apple.eawt.AboutHandler;
import com.apple.eawt.AppEvent.AboutEvent;
import com.apple.eawt.AppEvent.OpenFilesEvent;
import com.apple.eawt.AppEvent.PreferencesEvent;
import com.apple.eawt.AppEvent.QuitEvent;
import com.apple.eawt.Application;
import com.apple.eawt.OpenFilesHandler;
import com.apple.eawt.PreferencesHandler;
import com.apple.eawt.QuitHandler;
import com.apple.eawt.QuitResponse;

/**
 * Integrate KSE with Mac OS. Handles call backs from Mac OS.
 * 
 */
public class MacOsIntegration implements AboutHandler, OpenFilesHandler, PreferencesHandler, QuitHandler {
	private KseFrame kseFrame;
	private Application macOsApplicationIntegration;

	/**
	 * Construct integration with Mac OS.
	 * 
	 * @param kseFrame
	 *            KeyStore Explorer main frame
	 */
	public MacOsIntegration(KseFrame kseFrame) {
		this.kseFrame = kseFrame;
		macOsApplicationIntegration = Application.getApplication();

		macOsApplicationIntegration.setAboutHandler(this);
		macOsApplicationIntegration.setOpenFileHandler(this);
		macOsApplicationIntegration.setPreferencesHandler(this);
		macOsApplicationIntegration.setQuitHandler(this);
	}

	/**
	 * Handle about callback. Show application's about dialog.
	 * 
	 * @param evt
	 *            Event
	 */
	public void handleAbout(AboutEvent evt) {
		AboutAction aboutAction = new AboutAction(kseFrame);
		aboutAction.showAbout();
	}

	/**
	 * Handle open file callback. Open file in application.
	 * 
	 * @param evt
	 *            Event
	 */
	public void openFiles(OpenFilesEvent evt) {
		OpenAction openAction = new OpenAction(kseFrame);

		for (File file : evt.getFiles()) {
			openAction.openKeyStore(file);
		}
	}

	/**
	 * Handle preferences callback. Show application's preferences dialog.
	 * 
	 * @param evt
	 *            Event
	 */
	public void handlePreferences(PreferencesEvent evt) {
		PreferencesAction preferencesAction = new PreferencesAction(kseFrame);
		preferencesAction.showPreferences();
	}

	/**
	 * Handle quit callback. Quit application.
	 * 
	 * @param evt
	 *            Event
	 * @param resp
	 *            Response
	 */
	public void handleQuitRequestWith(QuitEvent evt, QuitResponse resp) {
		ExitAction exitAction = new ExitAction(kseFrame);
		exitAction.exitApplication();
		resp.cancelQuit(); // If we have retuned from the above call the user
							// has decied not to quit
	}
}
