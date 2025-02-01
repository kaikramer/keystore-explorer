/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

package org.kse.gui.preferences;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.kse.gui.components.JEscFrame;
import org.kse.gui.KseRestart;
import org.kse.gui.error.DError;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.gui.preferences.json.KseJacksonJrExtension;
import org.kse.gui.preferences.passwordmanager.EncryptedKeyStorePasswords;
import org.kse.utilities.os.OperatingSystem;

import com.fasterxml.jackson.jr.annotationsupport.JacksonAnnotationExtension;
import com.fasterxml.jackson.jr.ob.JSON;

/**
 * Load, provide access and store the application preferences and other config files of KSE like keystore passwords.
 * <p>
 *     The base directory for the config files is selected depending on the operating system:
 *     <ol>
 *     <li>On Windows %APPDATA% is used: <pre>c:\Users\<username>\AppData\Roaming\kse\</pre></li>
 *     <li>On Linux XDG_CONFIG_HOME or its default value is used: <pre>~/.config/kse</pre></li>
 *     <li>On MacOS "~/.config" is used for now, as other applications do this as well, but maybe switch later to
 *             ~/Library/Preferences or ~/Library/Application Support/</li> TODO
 *     </ol>
 * </p>
 *
 */
public class PreferencesManager {

    private static final String CONFIG_BASE_DIR = "kse";
    private static final String CONFIG_DOTTED_BASE_DIR = ".kse";
    private static final String CONFIG_FILE_NAME = "config.json";
    private static final String PASSWORDS_FILE_NAME = "keystore-passwords.json";
    private static final String ENV_VAR_CONFIG_DIR = "KSE_CONFIG_DIR";

    private static KsePreferences ksePreferences;
    private static EncryptedKeyStorePasswords keyStorePasswords;

    // configure jackson-jr
    private static final JSON json = JSON.builder()
                                         .register(JacksonAnnotationExtension.std)
                                         .register(new KseJacksonJrExtension())
                                         .build()
                                         .with(JSON.Feature.PRETTY_PRINT_OUTPUT)
                                         .with(JSON.Feature.WRITE_NULL_PROPERTIES)
                                         .with(JSON.Feature.FAIL_ON_DUPLICATE_MAP_KEYS);

    /**
     * Returns a singleton object of the application preferences.
     */
    public static KsePreferences getPreferences() {
        if (ksePreferences == null) {
            ksePreferences = loadPreferences();
        }
        return ksePreferences;
    }

    /**
     * Returns the encrypted keystore passwords and metadata from JSON file
     */
    public static EncryptedKeyStorePasswords getKeyStorePasswords() {
        if (keyStorePasswords == null) {
            keyStorePasswords = loadKeyStorePasswords();
        }
        return keyStorePasswords;
    }

    private static KsePreferences loadPreferences() {
        try {
            return json.beanFrom(KsePreferences.class, determineConfigFilePath());
        } catch (FileNotFoundException e) {
            // ignore, happens always on first run
            return new KsePreferences();
        } catch (Exception e) {
            DError.displayError(new JEscFrame(), e);
            return new KsePreferences();
        }
    }

    private static EncryptedKeyStorePasswords loadKeyStorePasswords() {
        try {
            return json.beanFrom(EncryptedKeyStorePasswords.class, determinePasswordsFilePath());
        } catch (FileNotFoundException e) {
            return new EncryptedKeyStorePasswords();
        } catch (Exception e) {
            DError.displayError(new JEscFrame(), e);
            return new EncryptedKeyStorePasswords();
        }
    }

    private static File determineConfigFilePath() throws IOException {

        // 1. Location with the highest priority: Config dir set from outside via env var
        File envDirConfigFile = new File(System.getenv(ENV_VAR_CONFIG_DIR), CONFIG_FILE_NAME);
        if (envDirConfigFile.exists()) {
            return envDirConfigFile.getCanonicalFile();
        }

        // 2. Config found in KSE base directory (where kse.jar is located)
        File kseInstallDirConfigFile = new File(System.getProperty(KseRestart.KSE_INSTALL_DIR), CONFIG_FILE_NAME);
        if (kseInstallDirConfigFile.exists()) {
            return kseInstallDirConfigFile.getCanonicalFile();
        }

        // 3. OS specific local/user config
        if (OperatingSystem.isWindows()) {
            return new File(getAppDataConfigDir(), CONFIG_FILE_NAME).getCanonicalFile();
        } else if (OperatingSystem.isLinux()) {
            return new File(getXdgConfigDir(), CONFIG_FILE_NAME).getCanonicalFile();
        } else if (OperatingSystem.isMacOs()){
            return new File(getXdgConfigDir(), CONFIG_FILE_NAME).getCanonicalFile();
        }

        // default to HOME dir
        return new File(System.getProperty("user.home"), ".kse" + File.separator + CONFIG_FILE_NAME);
    }

    private static File determinePasswordsFilePath() throws IOException {
        // location of passwords file should be right next to the config file
        return new File(determineConfigFilePath().getParentFile(), PASSWORDS_FILE_NAME).getCanonicalFile();
    }

    private static String getAppDataConfigDir() {
        String dir = System.getenv("APPDATA");
        if (dir == null || dir.trim().isEmpty()) {
            dir = System.getProperty("user.home") + File.separator + CONFIG_DOTTED_BASE_DIR;
        } else {
            dir += File.separator + CONFIG_BASE_DIR;
        }
        return dir;
    }

    private static String getXdgConfigDir() {
        String dir = System.getenv().get("XDG_CONFIG_HOME");
        // XDG spec: "If $XDG_CONFIG_HOME is either not set or empty, a default equal to $HOME/.config should be used."
        if (dir == null || dir.trim().isEmpty()) {
            dir = System.getProperty("user.home") + File.separator + ".config";
        }
        dir += File.separator + CONFIG_BASE_DIR;
        return dir;
    }

    /**
     * Save preferences to file
     */
    public static void persistPreferences() {
        try {
            File configFile = determineConfigFilePath();
            configFile.getParentFile().mkdirs();
            json.write(ksePreferences, configFile);
        } catch (Exception e) {
            DError.displayError(new JEscFrame(), e);
        }
    }

    /**
     * Save encrypted keystore passwords and metadata to JSON file
     */
    public static void persistKeyStorePasswords() {
        try {
            File passwordsFilePath = determinePasswordsFilePath();
            passwordsFilePath.getParentFile().mkdirs();
            json.write(keyStorePasswords, passwordsFilePath);
        } catch (Exception e) {
            DError.displayError(new JEscFrame(), e);
        }
    }
}
