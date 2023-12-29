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

import java.io.File;
import java.io.IOException;

import javax.swing.JFrame;

import org.kse.KSE;
import org.kse.gui.error.DError;

/**
 * Restart KeyStore Explorer.
 */
public class KseRestart {

    private static final String JAVA_HOME = "java.home";
    private static final String JAVA_CLASS_PATH = "java.class.path";

    private static final String KSE_INSTALL_DIR = "kse.install.dir";

    // macOS: location of native app stub (passed from appbundler)
    private static final String KSE_APP_STUB = "kse.app.stub";

    private static final String KSE_EXE = "kse.exe";
    private static final String KSE_APP = "kse.app";
    private static final String KSE_JAR = "kse.jar";

    private KseRestart() {
    }

    /**
     * Restart KeyStore Explorer in the same manner in which it was started.
     */
    public static void restart() {
        if (System.getProperty(KSE_EXE) != null) {
            restartAsKseExe();
        } else if (System.getProperty(KSE_APP) != null) {
            restartAsKseApp();
        } else if (System.getProperty(JAVA_CLASS_PATH).equals(KSE_JAR)) {
            restartAsKseJar();
        } else {
            restartAsKseClass();
        }
    }

    private static void restartAsKseExe() {
        File kseInstallDir = new File(System.getProperty(KSE_INSTALL_DIR));

        File kseExe = new File(kseInstallDir, KSE_EXE);

        String[] toExec = new String[] { kseExe.getPath() };

        try {
            Runtime.getRuntime().exec(toExec);
        } catch (IOException ex) {
            DError.displayError(new JFrame(), ex);
        }
    }

    private static void restartAsKseJar() {
        File javaBin = new File(new File(System.getProperty(JAVA_HOME), "bin"), "java");

        File kseInstallDir = new File(System.getProperty(KSE_INSTALL_DIR));

        File kseJar = new File(kseInstallDir, KSE_JAR);

        String[] toExec = new String[] { javaBin.getPath(), "-jar", kseJar.getPath() };

        try {
            Runtime.getRuntime().exec(toExec);
        } catch (IOException ex) {
            DError.displayError(new JFrame(), ex);
        }
    }

    private static void restartAsKseApp() {
        File javaAppStub = new File(System.getProperty(KSE_APP_STUB));

        String[] toExec = new String[] { javaAppStub.getPath() };

        try {
            Runtime.getRuntime().exec(toExec);
        } catch (IOException ex) {
            DError.displayError(new JFrame(), ex);
        }
    }

    private static void restartAsKseClass() {
        File javaBin = new File(new File(System.getProperty(JAVA_HOME), "bin"), "java");

        String kseClasspath = System.getProperty(JAVA_CLASS_PATH);

        String[] toExec = new String[] { javaBin.getPath(), "-classpath", kseClasspath, KSE.class.getName() };

        try {
            Runtime.getRuntime().exec(toExec);
        } catch (IOException ex) {
            DError.displayError(new JFrame(), ex);
        }
    }
}
