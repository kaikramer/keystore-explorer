/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2022 Kai Kramer
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
package org.kse.utilities;

import java.awt.event.WindowEvent;
import java.security.Security;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.gui.JEscDialog;

import com.formdev.flatlaf.FlatLightLaf;

/**
 * This is a helper class for quickly viewing KSE dialogs (mainly for testing purposes during development).
 */
public class DialogViewer {

    private DialogViewer() {
    }

    /**
     * Add BC provider and set l&f (only required when BC is needed before calling the run() method)
     */
    public static void prepare() throws UnsupportedLookAndFeelException {
        UIManager.setLookAndFeel(new FlatLightLaf());
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Create environment for showing the given dialog
     */
    public static void run(final JEscDialog dialog) throws UnsupportedLookAndFeelException {

        prepare();

        SwingUtilities.updateComponentTreeUI(dialog);

        SwingUtilities.invokeLater(() -> {

            dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                @Override
                public void windowClosing(java.awt.event.WindowEvent e) {
                    super.windowClosing(e);
                    System.exit(0);
                }

                @Override
                public void windowDeactivated(WindowEvent e) {
                    super.windowDeactivated(e);
                    System.exit(0);
                }
            });
            dialog.setLocationRelativeTo(null);
            dialog.setVisible(true);
        });
    }
}
