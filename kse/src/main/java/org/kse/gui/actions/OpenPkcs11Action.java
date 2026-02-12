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

import static org.kse.crypto.keystore.KeyStoreType.PKCS11;

import java.awt.Toolkit;
import java.awt.event.InputEvent;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.Provider;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DOpenPkcs11KeyStore;
import org.kse.gui.dialogs.PasswordCallbackHandler;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to open the PKCS11 KeyStore. If it does not exist provide the
 * user with the option of creating it.
 */
public class OpenPkcs11Action extends OpenAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public OpenPkcs11Action(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('1',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() +
                                                         InputEvent.SHIFT_DOWN_MASK));
        putValue(LONG_DESCRIPTION, res.getString("OpenPkcs11Action.statusbar"));
        putValue(NAME, res.getString("OpenPkcs11Action.text"));
        putValue(SHORT_DESCRIPTION, res.getString("OpenPkcs11Action.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/openpkcs11.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {

        try {
            DOpenPkcs11KeyStore dOpenPkcs11KeyStore = new DOpenPkcs11KeyStore(frame);
            dOpenPkcs11KeyStore.setLocationRelativeTo(frame);
            dOpenPkcs11KeyStore.setVisible(true);

            Provider selectedProvider = dOpenPkcs11KeyStore.getSelectedProvider();
            if (selectedProvider == null) {
                return;
            }

            KeyStore keyStore = KeyStore.getInstance(PKCS11.jce(), selectedProvider);

            // register password handler
            AuthProvider authProvider = (AuthProvider) selectedProvider;
            authProvider.setCallbackHandler(new PasswordCallbackHandler(frame));

            keyStore.load(null, null);

            var history = new KeyStoreHistory(new KseKeyStore(keyStore), selectedProvider.getName(), null, selectedProvider);

            kseFrame.addKeyStoreHistory(history);

        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }
}
