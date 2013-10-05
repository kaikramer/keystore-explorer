/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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
package net.sf.keystore_explorer;

import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.SplashScreen;
import java.io.File;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import net.sf.keystore_explorer.crypto.Password;
import net.sf.keystore_explorer.crypto.keystore.KeyStoreType;
import net.sf.keystore_explorer.crypto.keystore.KeyStoreUtil;
import net.sf.keystore_explorer.gui.CreateApplicationGui;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.os.OperatingSystem;
import net.sf.keystore_explorer.version.Version;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.WString;

/**
 * Main class to start the KeyStore Explorer (KSE) application.
 * 
 */
public class KSE {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/resources");

	public static final String APP_ID = "SourceForge.KeyStoreExplorer";
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
			// To take affect these must be set before the splash sceen is instantiated
			if (OperatingSystem.isMacOs()) {
				setAppleSystemProperties();
			} else if (OperatingSystem.isWindows7() || OperatingSystem.isWindows8()) {
				Shell32 shell32 = (Shell32) Native.loadLibrary("shell32", Shell32.class);
				shell32.SetCurrentProcessExplicitAppUserModelID(new WString(APP_ID)).longValue();
			}

			setInstallDirProperty();

			SplashScreen splash = SplashScreen.getSplashScreen();

			updateSplashMessage(splash, res.getString("KSE.LoadingApplicationSettings.splash.message"));
			ApplicationSettings applicationSettings = ApplicationSettings.getInstance();
			setCurrentDirectory(applicationSettings);

			updateSplashMessage(splash, res.getString("KSE.InitializingSecurity.splash.message"));
			initialiseSecurity();

			File keyStoreFile = null;

			if (args.length > 0) {
				keyStoreFile = new File(args[0]);
			}

			// Create application GUI on the event handler thread
			updateSplashMessage(splash, res.getString("KSE.CreatingApplicationGui.splash.message"));
			SwingUtilities.invokeLater(new CreateApplicationGui(applicationSettings, splash, keyStoreFile));
		} catch (Throwable t) {
			DError dError = new DError(new JFrame(), APPLICATION_MODAL, t);
			dError.setLocationRelativeTo(null);
			dError.setVisible(true);
			System.exit(1);
		}
	}

	private static void updateSplashMessage(SplashScreen splash, String message) {
		// Splash screen may not be present
		if (splash != null) {
			Font font = new Font(Font.SANS_SERIF, Font.PLAIN, 10);
			Graphics2D g = (Graphics2D) splash.createGraphics();
			g.setFont(font);
			g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

			// Wipe out any previous text
			g.setColor(new Color(238, 238, 238)); // #EEEEEE
			g.setPaintMode();
			g.fillRect(10, 60, 200, 15);

			// calculate centered position
			FontMetrics fm = g.getFontMetrics();
			int msgWidth = fm.stringWidth(message);
			int x = (230 / 2) - (msgWidth / 2);  
			
			// Draw next text
			g.setColor(new Color(96, 96, 96)); // #606060
			g.setPaintMode();
			g.drawString(message, x, 70);

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

	private static void initialiseSecurity() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException {
		
		// Add BouncyCastle provider
		Class<?> bcProvClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
		Provider bcProv = (Provider) bcProvClass.newInstance();
		Security.addProvider(bcProv);
		
		// Optimize performance of PKCS #12 by creating and saving a dummy PKCS
		// #12 KeyStore now - first use of PKCS 12 always lags - we take the hit
		// now so the user doesn't see lag when they first use PKCS 12
		try {
			KeyStore keyStore = KeyStoreUtil.create(KeyStoreType.PKCS12);
			File tmpFile = File.createTempFile("kse", "tmp");
			tmpFile.deleteOnExit();
			KeyStoreUtil.save(keyStore, tmpFile, new Password("123".toCharArray()));
		} catch (Exception ex) {
			ex.printStackTrace(); // Ignore - not essential that this works
		}
	}

	/**
	 * Get application name.
	 * 
	 * @return Application name
	 */
	public static String getApplicationName() {
		return res.getString("KSE.Name");
	}

	/**
	 * Get application version.
	 * 
	 * @return Application version
	 */
	public static Version getApplicationVersion() {
		return new Version(res.getString("KSE.Version"));
	}

	/**
	 * Get full application name, ie Name and Version.
	 * 
	 * @return Full application name
	 */
	public static String getFullApplicationName() {
		return MessageFormat.format(res.getString("KSE.FullName"), KSE.getApplicationName(),
				KSE.getApplicationVersion());
	}
}
