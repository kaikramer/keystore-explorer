/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

import java.awt.Desktop;
import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

import org.kse.gui.actions.AboutAction;
import org.kse.gui.actions.ExitAction;
import org.kse.gui.actions.OpenAction;
import org.kse.gui.actions.PreferencesAction;
import org.kse.version.JavaVersion;

/**
 * Integrate KSE with macOS. Handles call backs from macOS.
 */
public class MacOsIntegration implements InvocationHandler {

    private final KseFrame kseFrame;

    public MacOsIntegration(KseFrame kseFrame) {
        this.kseFrame = kseFrame;
    }

    public void addEventHandlers()
            throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException,
                   InstantiationException {

        if (JavaVersion.getJreVersion().isAtLeast(JavaVersion.JRE_VERSION_9)) {

            // using reflection to avoid Mac specific classes being required for compiling KSE on other platforms
            Class<?> quitHandlerClass = Class.forName("java.awt.desktop.QuitHandler");
            Class<?> aboutHandlerClass = Class.forName("java.awt.desktop.AboutHandler");
            Class<?> openFilesHandlerClass = Class.forName("java.awt.desktop.OpenFilesHandler");
            Class<?> prefsHandlerClass = Class.forName("java.awt.desktop.PreferencesHandler");

            Desktop desktop = Desktop.getDesktop();

            Object proxy = Proxy.newProxyInstance(MacOsIntegration.class.getClassLoader(),
                                                  new Class<?>[] { quitHandlerClass, aboutHandlerClass,
                                                                   openFilesHandlerClass, prefsHandlerClass }, this);

            desktop.getClass().getDeclaredMethod("setQuitHandler", quitHandlerClass).invoke(desktop, proxy);
            desktop.getClass().getDeclaredMethod("setAboutHandler", aboutHandlerClass).invoke(desktop, proxy);
            desktop.getClass().getDeclaredMethod("setOpenFileHandler", openFilesHandlerClass).invoke(desktop, proxy);
            desktop.getClass().getDeclaredMethod("setPreferencesHandler", prefsHandlerClass).invoke(desktop, proxy);
        } else {
            Class<?> applicationClass = Class.forName("com.apple.eawt.Application");
            Class<?> quitHandlerClass = Class.forName("com.apple.eawt.QuitHandler");
            Class<?> aboutHandlerClass = Class.forName("com.apple.eawt.AboutHandler");
            Class<?> openFilesHandlerClass = Class.forName("com.apple.eawt.OpenFilesHandler");
            Class<?> preferencesHandlerClass = Class.forName("com.apple.eawt.PreferencesHandler");

            Object application = applicationClass.getConstructor((Class[]) null).newInstance((Object[]) null);
            Object proxy = Proxy.newProxyInstance(MacOsIntegration.class.getClassLoader(),
                                                  new Class<?>[] { quitHandlerClass, aboutHandlerClass,
                                                                   openFilesHandlerClass, preferencesHandlerClass },
                                                  this);

            applicationClass.getDeclaredMethod("setQuitHandler", quitHandlerClass).invoke(application, proxy);
            applicationClass.getDeclaredMethod("setAboutHandler", aboutHandlerClass).invoke(application, proxy);
            applicationClass.getDeclaredMethod("setOpenFileHandler", openFilesHandlerClass).invoke(application, proxy);
            applicationClass.getDeclaredMethod("setPreferencesHandler", preferencesHandlerClass)
                            .invoke(application, proxy);
        }
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        switch (method.getName()) {
        case "openFiles":
            if (args[0] != null) {
                Object files = args[0].getClass().getMethod("getFiles").invoke(args[0]);
                if (files instanceof List) {
                    OpenAction openAction = new OpenAction(kseFrame);
                    for (File file : (List<File>) files) {
                        openAction.openKeyStore(file);
                    }
                }
            }
            break;
        case "handleQuitRequestWith":
            ExitAction exitAction = new ExitAction(kseFrame);
            exitAction.exitApplication();
            // If we have returned from the above call the user has decided not to quit
            if (args[1] != null) {
                args[1].getClass().getDeclaredMethod("cancelQuit").invoke(args[1]);
            }
            break;
        case "handleAbout":
            AboutAction aboutAction = new AboutAction(kseFrame);
            aboutAction.showAbout();
            break;
        case "handlePreferences":
            PreferencesAction preferencesAction = new PreferencesAction(kseFrame);
            preferencesAction.showPreferences();
            break;
        }
        return null;
    }

}