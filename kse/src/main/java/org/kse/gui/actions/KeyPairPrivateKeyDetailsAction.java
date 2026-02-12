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
package org.kse.gui.actions;

import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.security.PrivateKey;
import java.text.MessageFormat;
import java.util.Optional;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewPrivateKey;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to display the private key details for the selected key pair entry.
 */
public class KeyPairPrivateKeyDetailsAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public KeyPairPrivateKeyDetailsAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_MINUS, 0));
        putValue(LONG_DESCRIPTION, res.getString("KeyPairPrivateKeyDetailsAction.statusbar"));
        putValue(NAME, res.getString("KeyPairPrivateKeyDetailsAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("KeyPairPrivateKeyDetailsAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/privkeydetails.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        showPrivateKeySelectedEntry();
    }

    /**
     * Show the private details of the selected KeyStore entry.
     */
    public void showPrivateKeySelectedEntry() {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStoreState currentState = history.getCurrentState();

            String alias = kseFrame.getSelectedEntryAlias();

            Password password = getEntryPassword(alias, currentState);

            if (password == null) {
                return;
            }

            KseKeyStore keyStore = currentState.getKeyStore();

            PrivateKey privKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

            DViewPrivateKey dViewPrivateKey = new DViewPrivateKey(frame, MessageFormat.format(
                    res.getString("KeyPairPrivateKeyDetailsAction.PrivKeyDetailsEntry.Title"), alias), alias, privKey,
                                                                  preferences, Optional.empty());
            dViewPrivateKey.setLocationRelativeTo(frame);
            dViewPrivateKey.setVisible(true);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }
}
