/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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

import java.awt.Font;

import javax.swing.JLabel;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.plaf.metal.MetalLookAndFeel;

import org.kse.utilities.os.OperatingSystem;

import com.formdev.flatlaf.FlatDarculaLaf;
import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;

/**
 * Look and Feel utility methods.
 *
 */
public class LnfUtil {

	// VAqua LnF class as constant to avoid compile dependency
	private static final String VAQUA_LAF_CLASS = "org.violetlib.aqua.AquaLookAndFeel";

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
		// Flat LaF
		UIManager.installLookAndFeel("Flat Light", com.formdev.flatlaf.FlatLightLaf.class.getName());
		UIManager.installLookAndFeel("Flat Dark", com.formdev.flatlaf.FlatDarkLaf.class.getName());
		UIManager.installLookAndFeel("Flat IntelliJ", com.formdev.flatlaf.FlatIntelliJLaf.class.getName());
		UIManager.installLookAndFeel("Flat Darcula", com.formdev.flatlaf.FlatDarculaLaf.class.getName());

		// VAqua is optional
		if (OperatingSystem.isMacOs() && isVAquaAvailable()) {
			UIManager.installLookAndFeel("macOS (VAqua)", VAQUA_LAF_CLASS);
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
			UIManager.setLookAndFeel(lnfClassName);
		} catch (UnsupportedLookAndFeelException | ClassNotFoundException | InstantiationException
				| IllegalAccessException e) {
			// ignore
		}
	}

	/**
	 * Use the appropriate look and feel for the current platform.
	 *
	 * @return Look and feel class name used
	 */
	public static String useLnfForPlatform() {
		String lnfClassName = null;

		if (OperatingSystem.isMacOs() || OperatingSystem.isWindows()) {
			lnfClassName = UIManager.getSystemLookAndFeelClassName();
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
				lnfClassName = FlatLightLaf.class.getName();
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

		return OperatingSystem.isMacOs() && (
				UIManager.getSystemLookAndFeelClassName().equals(lnfClass) || lnfClass.equals(VAQUA_LAF_CLASS)) ;
	}

	/**
	 * Is the Metal l&f currently being used?
	 *
	 * @return True if it is
	 */
	public static boolean usingMetalLnf() {
		return usingLnf(MetalLookAndFeel.class.getName());
	}

	/**
	 * Is the Windows l&f currently being used?
	 *
	 * @return True if it is
	 */
	public static boolean usingWindowsLnf() {
		return usingLnf(UIManager.getSystemLookAndFeelClassName());
	}

	/**
	 * Is the supplied l&f currently being used?
	 *
	 * @return l&f class
	 */
	private static boolean usingLnf(String lnfClass) {
		String currentLnfClass = UIManager.getLookAndFeel().getClass().getName();
		return currentLnfClass.equals(lnfClass);
	}

	/**
	 * Does the currently active l&f use a dark color scheme?
	 */
	public static boolean isDarkLnf() {
		return UIManager.getLookAndFeel().getClass().isAssignableFrom(FlatDarkLaf.class)
				|| UIManager.getLookAndFeel().getClass().isAssignableFrom(FlatDarculaLaf.class);
	}

	/**
	 * Is optional VAqua LaF available?
	 */
	public static boolean isVAquaAvailable() {
		try {
			Class.forName(VAQUA_LAF_CLASS);
			return true;
		} catch (ClassNotFoundException e) {
			// VAqua jar not included
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
