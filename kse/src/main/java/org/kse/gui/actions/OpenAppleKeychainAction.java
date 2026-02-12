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

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.preferences.data.PasswordGeneratorSettings;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.rng.PasswordGenerator;

/**
 * Action to open the Apple Keychain KeyStore.
 */
public class OpenAppleKeychainAction extends OpenAction {

    private static final long serialVersionUID = -9068103518220241052L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public OpenAppleKeychainAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('A',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() +
                                                         InputEvent.SHIFT_DOWN_MASK));
        putValue(LONG_DESCRIPTION, res.getString("OpenAppleKeychainAction.statusbar"));
        putValue(NAME, res.getString("OpenAppleKeychainAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("OpenAppleKeychainAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/openapplekeychain.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {

        try {

            KseKeyStore openedKeyStore = KeyStoreUtil.loadAppleKeychain();

            var history = new KeyStoreHistory(openedKeyStore, res.getString("OpenAppleKeychainAction.TabTitle"), null, null);

            // The Apple security provider requires a password to import/export keychain entries,
            // but the password is irrelevant and not actually used. Keychain Access can export
            // entries created by KSE without using this password.

            // Sets the key store password so that the user doesn't have to be prompted for passwords
            // that won't be used and could be confusing for the user to understand.
            history.getCurrentState()
                    .setPassword(new Password(PasswordGenerator.generatePassword(new PasswordGeneratorSettings())));

            kseFrame.addKeyStoreHistory(history);

        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

}
