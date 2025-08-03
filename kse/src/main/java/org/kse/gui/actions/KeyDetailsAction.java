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
import java.awt.event.KeyEvent;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.MessageFormat;
import java.util.Optional;

import javax.crypto.SecretKey;
import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.crypto.CryptoException;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewPrivateKey;
import org.kse.gui.dialogs.DViewPublicKey;
import org.kse.gui.dialogs.DViewSecretKey;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to display details for the selected key entry.
 */
public class KeyDetailsAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public KeyDetailsAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0));
        putValue(LONG_DESCRIPTION, res.getString("KeyDetailsAction.statusbar"));
        putValue(NAME, res.getString("KeyDetailsAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("KeyDetailsAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/keydetails.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        showKeySelectedEntry();
    }

    /**
     * Show the key details of the selected KeyStore entry.
     */
    public void showKeySelectedEntry() {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStoreState currentState = history.getCurrentState();
            String alias = kseFrame.getSelectedEntryAlias();

            Password password = getEntryPassword(alias, currentState);

            if (password == null) {
                return;
            }

            KeyStore keyStore = currentState.getKeyStore();

            Key key = keyStore.getKey(alias, password.toCharArray());

            if (key instanceof SecretKey) {
                SecretKey secretKey = (SecretKey) key;

                DViewSecretKey dViewSecretKey = new DViewSecretKey(frame, MessageFormat.format(
                        res.getString("KeyDetailsAction.SecretKeyDetailsEntry.Title"), alias), secretKey, true);
                dViewSecretKey.setLocationRelativeTo(frame);
                dViewSecretKey.setVisible(true);

                if (dViewSecretKey.keyHasChanged()) {
                    updateSecretKey(currentState, alias, password, dViewSecretKey);
                }
            } else if (key instanceof PrivateKey) {
                PrivateKey privateKey = (PrivateKey) key;

                DViewPrivateKey dViewPrivateKey = new DViewPrivateKey(frame, MessageFormat.format(
                        res.getString("KeyDetailsAction.PrivateKeyDetailsEntry.Title"), alias), alias, privateKey,
                                                                      preferences, Optional.empty());
                dViewPrivateKey.setLocationRelativeTo(frame);
                dViewPrivateKey.setVisible(true);
            } else if (key instanceof PublicKey) {
                PublicKey publicKey = (PublicKey) key;

                DViewPublicKey dViewPublicKey = new DViewPublicKey(frame, MessageFormat.format(
                        res.getString("KeyDetailsAction.PublicKeyDetailsEntry.Title"), alias), publicKey);
                dViewPublicKey.setLocationRelativeTo(frame);
                dViewPublicKey.setVisible(true);
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private void updateSecretKey(KeyStoreState currentState, String alias, Password password,
                                 DViewSecretKey dViewSecretKey) throws CryptoException, KeyStoreException {
        KeyStore keyStore;
        KeyStoreState newState = currentState.createBasisForNextState(new GenerateSecretKeyAction(kseFrame));
        keyStore = newState.getKeyStore();
        SecretKey newSecretKey = dViewSecretKey.getSecretKey();
        keyStore.deleteEntry(alias);
        newState.removeEntryPassword(alias);
        keyStore.setKeyEntry(alias, newSecretKey, password.toCharArray(), null);
        newState.setEntryPassword(alias, password);
        currentState.append(newState);
        kseFrame.updateControls(true);
    }
}
