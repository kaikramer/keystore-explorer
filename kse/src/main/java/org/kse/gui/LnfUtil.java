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

import java.awt.Font;

import javax.swing.JLabel;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import org.kse.utilities.os.OperatingSystem;

import com.formdev.flatlaf.FlatDarculaLaf;
import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatIntelliJLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.themes.FlatMacDarkLaf;
import com.formdev.flatlaf.themes.FlatMacLightLaf;

/**
 * Look and Feel utility methods.
 */
public class LnfUtil {

    // VAqua LnF class as constant to avoid compile dependency
    private static final String VAQUA_LAF_CLASS = "org.violetlib.aqua.AquaLookAndFeel";

    private LnfUtil() {
    }

    /**
     * Do the supplied l&amp;f object and l&amp;f info object refer to the same
     * l&amp;f?
     *
     * @param lookAndFeel     L&amp;F object
     * @param lookAndFeelInfo L&amp;F info object
     * @return True if they do
     */
    public static boolean matchLnf(LookAndFeel lookAndFeel, UIManager.LookAndFeelInfo lookAndFeelInfo) {
        return lookAndFeel.getClass().getName().equals(lookAndFeelInfo.getClassName());
    }

    /**
     * Install L&amp;Fs.
     */
    public static void installLnfs() {
        // Flat LaF
        UIManager.installLookAndFeel("FlatLaf Light", FlatLightLaf.class.getName());
        UIManager.installLookAndFeel("FlatLaf Dark", FlatDarkLaf.class.getName());
        UIManager.installLookAndFeel("FlatLaf IntelliJ", FlatIntelliJLaf.class.getName());
        UIManager.installLookAndFeel("FlatLaf Darcula", FlatDarculaLaf.class.getName());
        UIManager.installLookAndFeel("FlatLaf macOS Light", FlatMacLightLaf.class.getName());
        UIManager.installLookAndFeel("FlatLaf macOS Dark", FlatMacDarkLaf.class.getName());

        // enable "eye" on password fields
        UIManager.put("PasswordField.showRevealButton", true);

        // VAqua is optional
        if (OperatingSystem.isMacOs() && isVAquaAvailable()) {
            UIManager.installLookAndFeel("macOS (VAqua)", VAQUA_LAF_CLASS);
        }
    }

    /**
     * Use supplied l&amp;f.
     *
     * @param lnfClassName L&amp;f class name
     */
    public static void useLnf(String lnfClassName) {
        try {
            UIManager.setLookAndFeel(lnfClassName);
        } catch (UnsupportedLookAndFeelException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            // ignore
        }
    }

    /**
     * Is a macOS l&amp;f currently being used?
     *
     * @return True if it is
     */
    public static boolean usingMacLnf() {
        String lnfClass = UIManager.getLookAndFeel().getClass().getName();

        return OperatingSystem.isMacOs() &&
               (UIManager.getSystemLookAndFeelClassName().equals(lnfClass) ||
                lnfClass.equals(FlatMacLightLaf.class.getName()) ||
                lnfClass.equals(FlatMacDarkLaf.class.getName()) ||
                lnfClass.equals(VAQUA_LAF_CLASS));
    }

    /**
     * Is the Windows l&amp;f currently being used?
     *
     * @return True if it is
     */
    public static boolean usingWindowsLnf() {
        return usingLnf(UIManager.getSystemLookAndFeelClassName());
    }

    /**
     * Is the supplied l&amp;f currently being used?
     *
     * @return l&amp;f class
     */
    private static boolean usingLnf(String lnfClass) {
        String currentLnfClass = UIManager.getLookAndFeel().getClass().getName();
        return currentLnfClass.equals(lnfClass);
    }

    /**
     * Does the currently active l&amp;f use a dark color scheme?
     */
    public static boolean isDarkLnf() {
        return UIManager.getLookAndFeel().getClass().isAssignableFrom(FlatDarkLaf.class) ||
               UIManager.getLookAndFeel().getClass().isAssignableFrom(FlatMacDarkLaf.class) ||
               UIManager.getLookAndFeel().getClass().isAssignableFrom(FlatDarculaLaf.class);
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
