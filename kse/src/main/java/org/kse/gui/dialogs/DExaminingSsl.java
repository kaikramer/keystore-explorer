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

import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.ssl.SslConnectionInfos;
import org.kse.utilities.ssl.SslUtils;

/**
 * Examines an SSL connection's certificates - a process which the user may
 * cancel at any time by pressing the cancel button.
 */
public class DExaminingSsl extends JWaitDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private String sslHost;
    private int sslPort;
    private KseKeyStore keyStore;
    private char[] password;
    private SslConnectionInfos sslInfos;

    /**
     * Creates a new DExaminingSsl dialog.
     *
     * @param parent        The parent frame
     * @param sslHost       SSL connection's host name
     * @param sslPort       SSL connection's port number
     * @param useClientAuth Try to connect with client certificate
     * @param ksh           KeyStore with client certificate
     */
    public DExaminingSsl(JFrame parent, String sslHost, int sslPort, boolean useClientAuth, KeyStoreHistory ksh) {
        super(parent, res.getString("DExaminingSsl.Title"), res.getString("DExaminingSsl.jlExaminingSsl.text"),
                "images/exssl.png", res.getString("DExaminingSsl.jbCancel.text"));

        this.sslHost = sslHost;
        this.sslPort = sslPort;

        if (useClientAuth) {
            this.keyStore = ksh.getCurrentState().getKeyStore();

            // some keystore types like MSCAPI and PKCS#11 have no password stored in their state
            Password pwd = ksh.getCurrentState().getPassword();
            if (pwd != null) {
                this.password = pwd.toCharArray();
            }
        }
    }

    /**
     * Start SSL connection examination in a separate thread.
     */
    public void startExamination() {
        startTask(new ExamineSsl());
    }

    /**
     * Get the SSL connection's certificates and some details like protocol version or cipher suite.
     *
     * @return The SSL connection's details or null if the user cancelled
     *         the dialog or an error occurred
     */
    public SslConnectionInfos getSSLConnectionInfos() {
        return sslInfos;
    }

    private class ExamineSsl implements Runnable {
        @Override
        public void run() {
            try {
                sslInfos = SslUtils.readSSLConnectionInfos(sslHost, sslPort, keyStore, password);

                SwingUtilities.invokeLater(() -> {
                    if (DExaminingSsl.this.isShowing()) {
                        closeDialog();
                    }
                });
            } catch (final Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (DExaminingSsl.this.isShowing()) {
                        String problemStr = MessageFormat.format(res.getString("DExaminingSsl.NoExamineSsl.Problem"),
                                                                 sslHost, "" + sslPort);

                        String[] causes = new String[] { res.getString("DExaminingSsl.SslHostPortIncorrect.Cause"),
                                                         res.getString("DExaminingSsl.SslHostUnavailable.Cause"),
                                                         res.getString("DExaminingSsl.ProxySettingsIncorrect.Cause") };

                        Problem problem = new Problem(problemStr, causes, ex);

                        DProblem dProblem = new DProblem(DExaminingSsl.this,
                                                         res.getString("DExaminingSsl.ProblemExaminingSsl.Title"),
                                                         problem);
                        dProblem.setLocationRelativeTo(DExaminingSsl.this);
                        dProblem.setVisible(true);

                        closeDialog();
                    }
                });
            }
        }
    }
}
