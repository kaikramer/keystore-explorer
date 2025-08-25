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
package org.kse.gui.actions;

import java.awt.Toolkit;
import java.security.KeyStore;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.KSE;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to unlock the selected key entry.
 */
public class UnlockKeyAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public UnlockKeyAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(LONG_DESCRIPTION, res.getString("UnlockKeyAction.statusbar"));
        putValue(NAME, res.getString("UnlockKeyAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("UnlockKeyAction.tooltip"));
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/unlock.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
        KeyStoreState currentState = history.getCurrentState();

        if (kseFrame.getSelectedEntryAliases().length > 1) {
            try {
                KeyStore keyStore = currentState.getKeyStore();

                for (String alias : kseFrame.getSelectedEntryAliases()) {
                    // Use isKeyEntry rather than the KSE isKeyPair/isKey utils since
                    // unlocking does not care if it's a secret key or key pair entry.
                    if (keyStore.isKeyEntry(alias)) {
                        // Use getEntryPassword for unlocking a multiple selection. It checks to
                        // see if the key is unlocked before calling unlock.
                        getEntryPassword(alias, currentState);
                    }
                }
            } catch (Exception ex) {
                DError.displayError(frame, ex);
            }
        } else {
            String alias = kseFrame.getSelectedEntryAlias();

            Password password = currentState.getEntryPassword(alias);

            if (password != null) {
                JOptionPane.showMessageDialog(frame, MessageFormat.format(
                                                      res.getString("UnlockKeyAction.KeyAlreadyUnlocked.message"), alias), KSE.getApplicationName(),
                                              JOptionPane.WARNING_MESSAGE);
                return;
            }

            unlockEntry(alias, currentState);
        }
    }
}
