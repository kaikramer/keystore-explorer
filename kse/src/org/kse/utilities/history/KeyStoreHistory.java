/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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

import java.io.File;
import java.security.KeyStore;
import java.security.Provider;

import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreType;

/**
 * Undo/redo history for a KeyStore.
 *
 */
public class KeyStoreHistory {
	private KeyStoreState initialState;
	private KeyStoreState currentState;
	private KeyStoreState savedState;
	private File file;
	private String name;
	private Provider explicitProvider;

	/**
	 * Create a new history for an unsaved KeyStore.
	 *
	 * @param keyStore
	 *            KeyStore
	 * @param name
	 *            KeyStore name
	 * @param password
	 *            KeyStore password
	 * @param explicitProvider
	 */
	public KeyStoreHistory(KeyStore keyStore, String name, Password password, Provider explicitProvider) {
		this.name = name;
		this.explicitProvider = explicitProvider;

		KeyStoreType type = KeyStoreType.resolveJce(keyStore.getType());

		if (type.isFileBased()) {
			initialState = new KeyStoreState(this, keyStore, password);
		} else {
			// we cannot handle state (which implies creating copies of the keystore in memory) for smartcards or alike
			initialState = new AlwaysIdenticalKeyStoreState(this, keyStore, password);
		}

		currentState = initialState;
	}

	/**
	 * Create a new history for a saved KeyStore.
	 *
	 * @param keyStore
	 *            KeyStore
	 * @param file
	 *            Save file
	 * @param password
	 *            KeyStore password
	 */
	public KeyStoreHistory(KeyStore keyStore, File file, Password password) {
		this.file = file;
		this.name = file.getName();
		initialState = new KeyStoreState(this, keyStore, password);
		currentState = initialState;
		savedState = initialState;
	}

	/**
	 * Get the current state in the history.
	 *
	 * @return Current state
	 */
	public KeyStoreState getCurrentState() {
		return currentState;
	}

	/**
	 * Null all passwords contained in the history.
	 */
	public void nullPasswords() {
		KeyStoreState state = initialState;

		while (true) {
			state.nullPasswords();
			state = state.nextState();

			if (state == null) {
				break;
			}
		}
	}

	/**
	 * Get the KeyStore's save file.
	 *
	 * @return The KeyStore save file or null if none is set
	 */
	public File getFile() {
		return file;
	}

	/**
	 * Set the KeyStore's save file.
	 *
	 * @param file
	 *            The KeyStore save file
	 */
	public void setFile(File file) {
		this.file = file;

		// Update name
		this.name = file.getName();
	}

	/**
	 * Get the KeyStore's path.
	 *
	 * @return Path if saved, otherwise use the name supplied on construction
	 */
	public String getPath() {
		if (file != null) {
			return file.getPath();
		} else {
			return getName();
		}
	}

	/**
	 * Get the KeyStore's name. This will be the save file name where there is
	 * one, otherwise it will be the name supplied upon construction.
	 *
	 * @return KeyStore name
	 */
	public String getName() {
		return name;
	}

	KeyStoreState getInitialState() {
		return initialState;
	}

	void setCurrentState(KeyStoreState state) {
		currentState = state;
	}

	KeyStoreState getSavedState() {
		return savedState;
	}

	void setSavedState(KeyStoreState state) {
		savedState = state;
	}

	public Provider getExplicitProvider() {
		return explicitProvider;
	}

	@Override
	public String toString() {
		return getName();
	}
}
