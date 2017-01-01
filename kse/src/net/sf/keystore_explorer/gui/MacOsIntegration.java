/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

import net.sf.keystore_explorer.gui.actions.AboutAction;
import net.sf.keystore_explorer.gui.actions.ExitAction;
import net.sf.keystore_explorer.gui.actions.OpenAction;
import net.sf.keystore_explorer.gui.actions.PreferencesAction;

/**
 * Integrate KSE with Mac OS. Handles call backs from Mac OS.
 */
public class MacOsIntegration implements InvocationHandler {

	private final KseFrame kseFrame;

	public MacOsIntegration(KseFrame kseFrame) {
		this.kseFrame = kseFrame;
	}

	public void addEventHandlers() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException,
	InvocationTargetException, InstantiationException {

		// using reflection to avoid Mac specific classes being required for compiling KSE on other platforms
		Class<?> applicationClass = Class.forName("com.apple.eawt.Application");
		Class<?> quitHandlerClass = Class.forName("com.apple.eawt.QuitHandler");
		Class<?> aboutHandlerClass = Class.forName("com.apple.eawt.AboutHandler");
		Class<?> openFilesHandlerClass = Class.forName("com.apple.eawt.OpenFilesHandler");
		Class<?> preferencesHandlerClass = Class.forName("com.apple.eawt.PreferencesHandler");

		Object application = applicationClass.getConstructor((Class[]) null).newInstance((Object[]) null);
		Object proxy = Proxy.newProxyInstance(MacOsIntegration.class.getClassLoader(), new Class<?>[]{
			quitHandlerClass, aboutHandlerClass, openFilesHandlerClass, preferencesHandlerClass}, this);

		applicationClass.getDeclaredMethod("setQuitHandler", quitHandlerClass).invoke(application, proxy);
		applicationClass.getDeclaredMethod("setAboutHandler", aboutHandlerClass).invoke(application, proxy);
		applicationClass.getDeclaredMethod("setOpenFileHandler", openFilesHandlerClass).invoke(application, proxy);
		applicationClass.getDeclaredMethod("setPreferencesHandler", preferencesHandlerClass).invoke(application,
				proxy);
	}

	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		if ("openFiles".equals(method.getName())) {
			if (args[0] != null) {
				Object files = args[0].getClass().getMethod("getFiles").invoke(args[0]);
				if (files instanceof List) {
					OpenAction openAction = new OpenAction(kseFrame);
					for (File file : (List<File>) files) {
						openAction.openKeyStore(file);
					}
				}
			}
		} else if ("handleQuitRequestWith".equals(method.getName())) {
			ExitAction exitAction = new ExitAction(kseFrame);
			exitAction.exitApplication();
			// If we have returned from the above call the user has decied not to quit
			if (args[1] != null) {
				args[1].getClass().getDeclaredMethod("cancelQuit").invoke(args[1]);
			}
		} else if ("handleAbout".equals(method.getName())) {
			AboutAction aboutAction = new AboutAction(kseFrame);
			aboutAction.showAbout();
		} else if ("handlePreferences".equals(method.getName())) {
			PreferencesAction preferencesAction = new PreferencesAction(kseFrame);
			preferencesAction.showPreferences();
		}
		return null;
	}

}