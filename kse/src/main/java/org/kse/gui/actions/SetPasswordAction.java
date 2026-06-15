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
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.cert.Certificate;
import java.util.Collections;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.CryptoException;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.passwordmanager.PasswordAndDecision;
import org.kse.gui.passwordmanager.PasswordManager;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to set the active KeyStore's password.
 */
public class SetPasswordAction extends KeyStoreExplorerAction implements HistoryAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public SetPasswordAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('P',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        putValue(LONG_DESCRIPTION, res.getString("SetPasswordAction.statusbar"));
        putValue(NAME, res.getString("SetPasswordAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("SetPasswordAction.tooltip"));
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/setpass.png"))));
    }

    @Override
    public String getHistoryDescription() {
        return res.getString("SetPasswordAction.History.text");
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        try {
            if (setKeyStorePassword()) {
                JOptionPane.showMessageDialog(frame,
                                              res.getString("SetPasswordAction.SetKeyStorePasswordSuccessful.message"),
                                              res.getString("SetPasswordAction.SetKeyStorePassword.Title"),
                                              JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    /**
     * Set the active KeyStore's password.
     *
     * @return True if successful
     * @throws CryptoException If problem occurred
     */
    protected boolean setKeyStorePassword() throws CryptoException {
        KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

        KeyStoreState currentState = history.getCurrentState();
        KeyStoreState newState = currentState.createBasisForNextState(this);

        // don't ask user whether they want to use the password manager if they already answered with "yes" or
        // if the keystore password is already stored in the password manager
        boolean askUserForPasswordManager = !(newState.isStoredInPasswordManager() ||
                PasswordManager.getInstance().isKeyStorePasswordKnown(history.getFile()));
        boolean isPasswordManagerWanted = newState.isStoredInPasswordManager();

        PasswordAndDecision passwordAndDecision = getNewKeyStorePassword(askUserForPasswordManager,
                                                                         isPasswordManagerWanted);
        Password password = passwordAndDecision.getPassword();

        if (password == null) {
            return false;
        }

        newState.setPassword(password);

        reEncryptKeyEntriesIfNeeded(currentState, newState, password);

        newState.setStoredInPasswordManager(passwordAndDecision.isSavePassword());

        currentState.append(newState);

        kseFrame.updateControls(true);

        return true;
    }

    /**
     * Re-encrypt key pair entries with the new key store password where the key store format does
     * not do this itself on save.
     * <p>
     * A KDB (CMS) key database encrypts every private key with the key store password and writes the
     * encrypted keys back unchanged when saved. Unlike PKCS #12, storing it with a new password only
     * re-signs the header - the keys stay encrypted with the old password and would become unreadable
     * after the change. The keys are therefore re-encrypted here, while the old password is still known.
     */
    private void reEncryptKeyEntriesIfNeeded(KeyStoreState currentState, KeyStoreState newState,
                                             Password newPassword) throws CryptoException {
        if (currentState.getType() != KeyStoreType.KDB) {
            return;
        }

        Password oldPassword = currentState.getPassword();
        if (oldPassword == null || oldPassword.equals(newPassword)) {
            return;
        }

        try {
            KseKeyStore keyStore = newState.getKeyStore();
            for (String alias : Collections.list(keyStore.aliases())) {
                if (KeyStoreUtil.isKeyPairEntry(alias, keyStore)) {
                    Key key = keyStore.getKey(alias, oldPassword.toCharArray());
                    Certificate[] chain = keyStore.getCertificateChain(alias);
                    keyStore.setKeyEntry(alias, key, newPassword.toCharArray(), chain);
                    newState.setEntryPassword(alias, new Password(newPassword));
                }
            }
        } catch (GeneralSecurityException ex) {
            throw new CryptoException(res.getString("SetPasswordAction.NoReEncryptEntries.exception.message"), ex);
        }
    }
}
