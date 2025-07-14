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

package org.kse.utilities.history;

import java.security.KeyStore;

import org.kse.gui.passwordmanager.Password;

/**
 * Special version of KeyStoreState for key stores that cannot be copied, but the
 * changes are only persisted once the key store is saved (e.g., Apple Keychain).
 */
public class SaveableNonFileKeyStoreState extends AlwaysIdenticalKeyStoreState {

    // Default to saved since the key store matches the backing store when first opened.
    private boolean isSaved = true;

    /**
     * Create a new state.
     *
     * @param history  History
     * @param keyStore KeyStore
     * @param password KeyStore password
     */
    SaveableNonFileKeyStoreState(KeyStoreHistory history, KeyStore keyStore, Password password) {
        super(history, keyStore, password);
    }

    @Override
    public boolean isInitialState() {
        // The close action also checks that the state isn't the initial state
        // before prompting a save. Therefore, link the initial state to the
        // saved state so that the user is prompted to save unsaved changes.
        return isSaved;
    }

    @Override
    public boolean isSavedState() {
        return isSaved;
    }

    @Override
    public void setAsSavedState() {
        isSaved = true;
    }

    @Override
    public void append(KeyStoreState keyStoreState) {
        isSaved = false;
    }

}
