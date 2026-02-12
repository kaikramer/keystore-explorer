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
import java.awt.event.InputEvent;
import java.text.MessageFormat;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.secretkey.PasswordType;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DGetAlias;
import org.kse.gui.dialogs.DStorePassphrase;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to store a passphrase in a key store.
 */
public class StorePassphraseAction extends KeyStoreExplorerAction implements HistoryAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public StorePassphraseAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('P',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() +
                                                         InputEvent.ALT_DOWN_MASK));
        putValue(LONG_DESCRIPTION, res.getString("StorePassphraseAction.statusbar"));
        putValue(NAME, res.getString("StorePassphraseAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("StorePassphraseAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/passphrase.png"))));
    }

    @Override
    public String getHistoryDescription() {
        return (String) getValue(NAME);
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        storePassphrase();
    }

    /**
     * Generate a secret key in the currently opened KeyStore.
     */
    private void storePassphrase() {
        try {
            PasswordType passphraseType = preferences.getKeyGenerationDefaults().getPasswordType();

            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStoreState currentState = history.getCurrentState();

            DStorePassphrase dStorePassphrase = new DStorePassphrase(frame, currentState.getType(), passphraseType);
            dStorePassphrase.setLocationRelativeTo(frame);
            dStorePassphrase.setVisible(true);

            if (!dStorePassphrase.isSuccessful()) {
                return;
            }

            passphraseType = dStorePassphrase.getPasswordType();
            Password passphrase = dStorePassphrase.getPassphrase();

            preferences.getKeyGenerationDefaults().setPasswordType(passphraseType);

            byte[] newPass = passphrase.toByteArray();
            SecretKey secretKey = new SecretKeySpec(newPass, passphraseType.jce());

            KeyStoreState newState = currentState.createBasisForNextState(this);

            KseKeyStore keyStore = newState.getKeyStore();
            KeyStoreType keyStoreType = KeyStoreType.resolveJce(keyStore.getType());

            DGetAlias dGetAlias = new DGetAlias(frame,
                                                res.getString("StorePassphraseAction.NewPassphraseEntryAlias.Title"),
                                                null);
            dGetAlias.setLocationRelativeTo(frame);
            dGetAlias.setVisible(true);
            String alias = keyStoreType.normalizeAlias(dGetAlias.getAlias());

            if (alias == null) {
                return;
            }

            if (keyStore.containsAlias(alias)) {
                String message = MessageFormat.format(res.getString("StorePassphraseAction.OverWriteEntry.message"),
                                                      alias);

                int selected = JOptionPane.showConfirmDialog(frame, message, res.getString(
                        "StorePassphraseAction.NewPassphraseEntryAlias.Title"), JOptionPane.YES_NO_OPTION);
                if (selected != JOptionPane.YES_OPTION) {
                    return;
                }
            }

            Password password = getNewEntryPassword(keyStoreType,
                    res.getString("StorePassphraseAction.NewPassphraseEntryPassword.Title"), currentState, newState);
            if (password == null) {
                return;
            }

            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
                newState.removeEntryPassword(alias);
            }

            keyStore.setKeyEntry(alias, secretKey, password.toCharArray(), null);
            newState.setEntryPassword(alias, password);

            currentState.append(newState);

            kseFrame.updateControls(true);

            JOptionPane.showMessageDialog(frame, res.getString(
                                                  "StorePassphraseAction.PassphraseStoreSuccessful.message"),
                                          res.getString("StorePassphraseAction.StorePassphrase.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }
}
