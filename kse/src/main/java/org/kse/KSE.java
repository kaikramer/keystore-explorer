/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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

import java.awt.Toolkit;
import java.io.File;
import java.lang.reflect.Field;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.crypto.csr.pkcs12.Pkcs12Util;
import org.kse.crypto.x509.KseX500NameStyle;
import org.kse.gui.CreateApplicationGui;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.KseRestart;
import org.kse.gui.error.DError;
import org.kse.gui.preferences.PreferencesManager;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.gui.preferences.data.LanguageItem;
import org.kse.utilities.net.ProxySettingsUpdater;
import org.kse.utilities.os.OperatingSystem;
import org.kse.version.JavaVersion;
import org.kse.version.Version;

/**
 * Main class to start the KeyStore Explorer (KSE) application.
 */
public class KSE {
    private static final ResourceBundle props = ResourceBundle.getBundle("org/kse/version");

    public static Provider BC = new BouncyCastleProvider();

    static {
        // set default style for Bouncy Castle's X500Name class
        X500Name.setDefaultStyle(KseX500NameStyle.INSTANCE);

        // we start with system proxy settings and switch later depending on preferences
        System.setProperty("java.net.useSystemProxies", "true");

        // allow lax parsing of malformed ASN.1 integers
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "true");
    }

    /**
     * Start the KeyStore Explorer application. Takes one optional argument -
     * the location of a KeyStore file to open upon startup.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            // To take effect these must be set before the splash screen is instantiated
            if (OperatingSystem.isMacOs()) {
                setAppleSystemProperties();
            } else if (OperatingSystem.isLinux()) {
                fixAppClassName();
            }

            setInstallDirProperty();

            KsePreferences preferences = PreferencesManager.getPreferences();
            setCurrentDirectory(preferences.getCurrentDirectory());

            ProxySettingsUpdater.updateSystem(preferences.getProxySettings());

            String language = preferences.getLanguage();
            if (!language.equals(LanguageItem.SYSTEM_LANGUAGE)) {
                Locale.setDefault(new Locale(language));
            }

            Security.addProvider(BC);

            Pkcs12Util.setEncryptionStrength(preferences.getPkcs12EncryptionSetting());

            setProperties(preferences.getProperties());

            // list of files to open after start
            List<File> parameterFiles = new ArrayList<>();
            for (String arg : args) {
                File parameterFile = new File(arg);
                if (parameterFile.exists()) {
                    parameterFiles.add(parameterFile);
                }
            }

            SwingUtilities.invokeLater(new CreateApplicationGui(preferences, parameterFiles));
        } catch (Throwable t) {
            DError dError = new DError(new JFrame(), t);
            dError.setLocationRelativeTo(null);
            dError.setVisible(true);
            System.exit(1);
        }
    }

    private static void setProperties(Map<String, String> properties) {
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            System.setProperty(entry.getKey(), entry.getValue());
        }
    }

    private static void fixAppClassName() {
        // Fix application name in Gnome top bar, see http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6528430
        // TODO Bug is not fixed yet, but the workaround causes an "Illegal reflective access" warning since Java 9...
        if (JavaVersion.getJreVersion().isBelow(JavaVersion.JRE_VERSION_12)) {
            Toolkit xToolkit = Toolkit.getDefaultToolkit();
            try {
                Field awtAppClassNameField = xToolkit.getClass().getDeclaredField("awtAppClassName");
                awtAppClassNameField.setAccessible(true);
                awtAppClassNameField.set(xToolkit, getApplicationName());
            } catch (Exception x) {
                // ignore
            }
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
        // Use this for restarts; install directory is always user.dir, but we change user.dir in CurrentDirectory class
        System.setProperty(KseRestart.KSE_INSTALL_DIR, System.getProperty("user.dir"));
    }

    private static void setCurrentDirectory(String currentDir) {
        if (currentDir != null) {
            CurrentDirectory.update(new File(currentDir));
        }
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
     * Get user manual version (for link to online help).
     *
     * @return Application version
     */
    public static Version getUserManualVersion() {
        return new Version(props.getString("KSE.UserManual.Version"));
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
