/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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
package org.kse.gui.dialogs;

import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.version.Version;
import org.kse.version.VersionCheck;

/**
 * Check for an updated version of KeyStore Explorer. This check works over the
 * net so the user may cancel at any time by pressing the cancel button.
 */
public class DCheckUpdate extends JWaitDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private Version latestVersion;

    /**
     * Creates a new DCheckUpdate dialog.
     *
     * @param parent The parent frame
     */
    public DCheckUpdate(JFrame parent) {
        super(parent, res.getString("DCheckUpdate.Title"), res.getString("DCheckUpdate.jlCheckUpdate.text"),
                "images/chkup.png", res.getString("DCheckUpdate.jbCancel.text"));
    }

    /**
     * Start key pair generation in a separate thread.
     */
    public void startCheck() {
        startTask(new CheckForUpdate());
    }

    /**
     * Get latest version found by check.
     *
     * @return latest version or null if none found.
     */
    public Version getLatestVersion() {
        return latestVersion;
    }

    private class CheckForUpdate implements Runnable {
        @Override
        public void run() {
            try {
                latestVersion = VersionCheck.getLatestVersion();

                SwingUtilities.invokeLater(() -> closeDialog());
            } catch (final Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (DCheckUpdate.this.isShowing()) {
                        String problemStr = res.getString("DCheckUpdate.NoCheckUpdate.Problem");

                        String[] causes = new String[] { res.getString("DCheckUpdate.UpdateHostUnavailable.Cause"),
                                                         res.getString("DCheckUpdate.ProxySettingsIncorrect.Cause") };

                        Problem problem = new Problem(problemStr, causes, ex);

                        DProblem dProblem = new DProblem(DCheckUpdate.this,
                                                         res.getString("DCheckUpdate.ProblemCheckingUpdate.Title"),
                                                         problem);
                        dProblem.setLocationRelativeTo(DCheckUpdate.this);
                        dProblem.setVisible(true);

                        closeDialog();
                    }
                });
            }
        }
    }
}
