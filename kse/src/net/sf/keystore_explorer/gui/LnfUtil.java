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

import java.awt.Font;

import javax.swing.JLabel;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.plaf.metal.MetalLookAndFeel;

import com.jgoodies.looks.plastic.Plastic3DLookAndFeel;
import com.jgoodies.looks.plastic.theme.SkyBlue;
import com.sun.java.swing.plaf.windows.WindowsClassicLookAndFeel;
import com.sun.java.swing.plaf.windows.WindowsLookAndFeel;

import net.sf.keystore_explorer.gui.theme.LightOceanTheme;
import net.sf.keystore_explorer.utilities.os.OperatingSystem;
import net.sf.keystore_explorer.version.JavaVersion;

/**
 * Look and Feel utility methods.
 *
 */
public class LnfUtil {

	// Darcula LnF class as constant to avoid compile dependency
	private static final String DARCULA_LAF_CLASS = "com.bulenkov.darcula.DarculaLaf";

	private LnfUtil() {
	}

	/**
	 * Do the supplied l&f object and l&f info object refer to the same l&f?
	 *
	 * @param lookAndFeel
	 *            L&F object
	 * @param lookAndFeelInfo
	 *            L&F info object
	 * @return True if they do
	 */
	public static boolean matchLnf(LookAndFeel lookAndFeel, UIManager.LookAndFeelInfo lookAndFeelInfo) {
		return lookAndFeel.getClass().getName().equals(lookAndFeelInfo.getClassName());
	}

	/**
	 * Install L&Fs.
	 */
	public static void installLnfs() {
		UIManager.installLookAndFeel("JGoodies Plastic 3D", Plastic3DLookAndFeel.class.getName());

		if (OperatingSystem.isWindows()) {
			UIManager.installLookAndFeel("JGoodies Windows", com.jgoodies.looks.windows.WindowsLookAndFeel.class.getName());
		}

		// Darcula is optional
		if (isDarculaAvailable()) {
		    UIManager.installLookAndFeel("Darcula", DARCULA_LAF_CLASS);
		}
	}

	/**
	 * Use supplied l&f.
	 *
	 * @param lnfClassName
	 *            L&f class name
	 */
	public static void useLnf(String lnfClassName) {
		try {
			// Make l&f specific settings - required before setting the l&f
			if (lnfClassName.equals(Plastic3DLookAndFeel.class.getName())) {
				MetalLookAndFeel.setCurrentTheme(new SkyBlue());
				UIManager.put("jgoodies.useNarrowButtons", Boolean.FALSE);
			} else if (lnfClassName.equals(com.jgoodies.looks.windows.WindowsLookAndFeel.class.getName())) {
				UIManager.put("jgoodies.useNarrowButtons", Boolean.FALSE);
			} else if (lnfClassName.equals(MetalLookAndFeel.class.getName())) {
				// Lighten metal/ocean
				MetalLookAndFeel.setCurrentTheme(new LightOceanTheme());
			}

			UIManager.setLookAndFeel(lnfClassName);
		} catch (UnsupportedLookAndFeelException e) {
		} catch (ClassNotFoundException e) {
		} catch (InstantiationException e) {
		} catch (IllegalAccessException e) {
		}
	}

	/**
	 * Use the appropriate look and feel for the current platform.
	 *
	 * @return Look and feel class name used
	 */
	public static String useLnfForPlatform() {
		String lnfClassName = null;

		if (OperatingSystem.isMacOs()) {
			lnfClassName = UIManager.getSystemLookAndFeelClassName();
		} else if (OperatingSystem.isWindows()) {
			lnfClassName = WindowsLookAndFeel.class.getName();
		} else {
			String xdgCurrentDesktop = System.getenv("XDG_CURRENT_DESKTOP");
			if ("Unity".equalsIgnoreCase(xdgCurrentDesktop)
					|| "XFCE".equalsIgnoreCase(xdgCurrentDesktop)
					|| "GNOME".equalsIgnoreCase(xdgCurrentDesktop)
					|| "X-Cinnamon".equalsIgnoreCase(xdgCurrentDesktop)
					|| "LXDE".equalsIgnoreCase(xdgCurrentDesktop)
					) {
				lnfClassName = UIManager.getSystemLookAndFeelClassName();
			} else {
				lnfClassName = Plastic3DLookAndFeel.class.getName();
			}
		}

		useLnf(lnfClassName);

		return lnfClassName;
	}

	/**
	 * Is a Mac l&f (Aqua) currently being used?
	 *
	 * @return True if it is
	 */
	public static boolean usingMacLnf() {
		String lnfClass = UIManager.getLookAndFeel().getClass().getName();

		return OperatingSystem.isMacOs() && UIManager.getSystemLookAndFeelClassName().equals(lnfClass);
	}

	/**
	 * Is the JGoodies Plastic 3D l&f currently being used?
	 *
	 * @return True if it is
	 */
	public static boolean usingPlastic3DLnf() {
		return usingLnf(Plastic3DLookAndFeel.class);
	}

	/**
	 * Is the Metal l&f currently being used?
	 *
	 * @return True if it is
	 */
	public static boolean usingMetalLnf() {
		return usingLnf(MetalLookAndFeel.class);
	}

	/**
	 * Is the Windows l&f currently being used?
	 *
	 * @return True if it is
	 */
	public static boolean usingWindowsLnf() {
		return usingLnf(WindowsLookAndFeel.class);
	}

	/**
	 * Is the Windows Classic l&f currently being used?
	 *
	 * @return True if it is
	 */
	public static boolean usingWindowsClassicLnf() {
		return usingLnf(WindowsClassicLookAndFeel.class);
	}

	/**
	 * Is the supplied l&f currently being used?
	 *
	 * @return l&f class
	 */
	private static boolean usingLnf(Class lnfClass) {
		String currentLnfClass = UIManager.getLookAndFeel().getClass().getName();
		return currentLnfClass.equals(lnfClass.getName());
	}

	/**
	 * Does the currently active l&f use a dark color scheme?
	 */
	public static boolean isDarkLnf() {
		return UIManager.getLookAndFeel().getClass().getName().equals(DARCULA_LAF_CLASS);
	}

	/**
	 * Is optional Darcula LaF available?
	 */
	public static boolean isDarculaAvailable() {
		try {
			Class.forName(DARCULA_LAF_CLASS);
			// Darcula has some issues in Java 6
			if (JavaVersion.getJreVersion().isAtLeast(JavaVersion.JRE_VERSION_170)) {
				return true;
			}
		} catch (ClassNotFoundException e) {
			// Darcula jar not included
		}
		return false;
	}

	/**
	 * Get default font size for a label.
	 *
	 * @return Font size
	 */
	public static int getDefaultFontSize() {
		Font defaultFont = new JLabel().getFont();
		return defaultFont.getSize();
	}
}
