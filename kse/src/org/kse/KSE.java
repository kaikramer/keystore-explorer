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
package org.kse;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.SplashScreen;
import java.awt.Toolkit;
import java.io.File;
import java.lang.reflect.Field;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.crypto.x509.KseX500NameStyle;
import org.kse.gui.CreateApplicationGui;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.error.DError;
import org.kse.utilities.os.OperatingSystem;
import org.kse.version.Version;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.WString;

/**
 * Main class to start the KeyStore Explorer (KSE) application.
 *
 */
public class KSE {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/resources");
	private static ResourceBundle props = ResourceBundle.getBundle("org/kse/version");

	static {
		// set default style for Bouncy Castle's X500Name class
		X500Name.setDefaultStyle(KseX500NameStyle.INSTANCE);

		// we start with system proxy settings and switch later depending on preferences
		System.setProperty("java.net.useSystemProxies", "true");

		// allow lax parsing of malformed ASN.1 integers
		System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "true");
	}

	public interface Shell32 extends Library {
		NativeLong SetCurrentProcessExplicitAppUserModelID(WString appID);
	}

	/**
	 * Start the KeyStore Explorer application. Takes one optional argument -
	 * the location of a KeyStore file to open upon startup.
	 *
	 * @param args
	 *            the command line arguments
	 */
	public static void main(String args[]) {
		try {
			// To take affect these must be set before the splash screen is instantiated
			if (OperatingSystem.isMacOs()) {
				setAppleSystemProperties();
			} else if (OperatingSystem.isWindows7() || OperatingSystem.isWindows8() || OperatingSystem.isWindows10()) {
				String appId = props.getString("KSE.AppUserModelId");
				Shell32 shell32 = (Shell32) Native.loadLibrary("shell32", Shell32.class);
				shell32.SetCurrentProcessExplicitAppUserModelID(new WString(appId)).longValue();
			} else if (OperatingSystem.isLinux()) {
				fixAppClassName();
			}

			setInstallDirProperty();

			SplashScreen splash = SplashScreen.getSplashScreen();

			updateSplashMessage(splash, res.getString("KSE.LoadingApplicationSettings.splash.message"));
			ApplicationSettings applicationSettings = ApplicationSettings.getInstance();
			setCurrentDirectory(applicationSettings);

			updateSplashMessage(splash, res.getString("KSE.InitializingSecurity.splash.message"));
			initialiseSecurity();

			// list of files to open after start
			List<File> parameterFiles = new ArrayList<File>();
			for (String arg : args) {
				File parameterFile = new File(arg);
				if (parameterFile.exists()) {
					parameterFiles.add(parameterFile);
				}
			}

			// Create application GUI on the event handler thread
			updateSplashMessage(splash, res.getString("KSE.CreatingApplicationGui.splash.message"));
			SwingUtilities.invokeLater(new CreateApplicationGui(applicationSettings, splash, parameterFiles));
		} catch (Throwable t) {
			DError dError = new DError(new JFrame(), t);
			dError.setLocationRelativeTo(null);
			dError.setVisible(true);
			System.exit(1);
		}
	}

	private static void fixAppClassName() {
		// Fix application name in Gnome top bar, see http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6528430
		Toolkit xToolkit = Toolkit.getDefaultToolkit();
		try {
			Field awtAppClassNameField = xToolkit.getClass().getDeclaredField("awtAppClassName");
			awtAppClassNameField.setAccessible(true);
			awtAppClassNameField.set(xToolkit, getApplicationName());
		} catch (Exception x) {
			// ignore
		}
	}

	private static void updateSplashMessage(SplashScreen splash, String message) {
		// Splash screen may not be present
		if (splash != null) {
			Font font = new Font(Font.SANS_SERIF, Font.PLAIN, 10);
			Graphics2D g = splash.createGraphics();
			g.setFont(font);
			g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

			// Wipe out any previous text
			g.setColor(new Color(238, 238, 238)); // #EEEEEE
			g.setPaintMode();
			g.fillRect(12, 70, 250, 30); // (x,y) is top left corner of area

			// Draw next text
			g.setColor(new Color(96, 96, 96)); // #606060
			g.setPaintMode();
			g.drawString(message, 17, 86); // (x,y) is baseline of text

			splash.update();
		}
	}

	private static void setAppleSystemProperties() {
		try {
			// On Apple use screen bar for menus
			System.setProperty("apple.laf.useScreenMenuBar", "true");

			// On Apple set the menu about name to the application name
			System.setProperty("com.apple.mrj.application.apple.menu.about.name", getApplicationName());
		} catch (SecurityException ex) {
			ex.printStackTrace(); // Ignore - not essential that this works
		}
	}

	private static void setInstallDirProperty() {
		// Use this for restarts
		// Install directory is always user.dir, but we change user.dir in CurrentDirectory class
		System.setProperty("kse.install.dir", System.getProperty("user.dir"));
	}

	private static void setCurrentDirectory(ApplicationSettings applicationSettings) {
		File currentDirectory = applicationSettings.getCurrentDirectory();

		if (currentDirectory != null) {
			CurrentDirectory.update(currentDirectory);
		}
	}

	private static void initialiseSecurity()  {

		// Add BouncyCastle provider
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Get application name.
	 *
	 * @return Application name
	 */
	public static String getApplicationName() {
		return props.getString("KSE.Name");
	}

	/**
	 * Get application version.
	 *
	 * @return Application version
	 */
	public static Version getApplicationVersion() {
		return new Version(props.getString("KSE.Version"));
	}

	/**
	 * Get full application name, ie Name and Version.
	 *
	 * @return Full application name
	 */
	public static String getFullApplicationName() {
		return MessageFormat.format(props.getString("KSE.FullName"), KSE.getApplicationName(),
				KSE.getApplicationVersion());
	}
}
