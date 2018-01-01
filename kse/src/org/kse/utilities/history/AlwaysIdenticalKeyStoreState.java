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

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ResourceBundle;

import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;

/**
 * Special version of KeyStoreState for KeyStores that cannot be copied (like PKCS#11).
 *
 */
public class AlwaysIdenticalKeyStoreState extends KeyStoreState {

	/** Resource bundle */
	protected static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/utilities/history/resources");

	/**
	 * Create an empty state.
	 */
	AlwaysIdenticalKeyStoreState() {
		super();
	}

	/**
	 * Create a new state.
	 *
	 * @param history
	 *            History
	 * @param keyStore
	 *            KeyStore
	 * @param password
	 *            KeyStore password
	 */
	AlwaysIdenticalKeyStoreState(KeyStoreHistory history, KeyStore keyStore, Password password) {
		super(history, keyStore, password);
	}

	@Override
	public boolean isSavedState() {
		return true;
	}

	@Override
	public void setAsSavedState() {
		// do nothing
	}

	@Override
	public void append(KeyStoreState keyStoreState) {
		// do nothing
	}

	@Override
	public void setPreviousStateAsCurrentState() throws CryptoException {
		// do nothing
	}

	@Override
	public void setNextStateAsCurrentState() throws CryptoException {
		// do nothing
	}

	@Override
	public KeyStoreState previousState() {
		return this;
	}

	@Override
	public KeyStoreState nextState() {
		return null;
	}

	@Override
	public KeyStoreState createBasisForNextState(HistoryAction action) throws CryptoException {
		return this;
	}

	@Override
	protected void propagateNewPasswords(KeyStoreState targetState) throws CryptoException {
		// do nothing
	}

	@Override
	protected boolean isEntryPrivateKeyEqual(KeyStoreState targetState, String alias, Password password)
			throws GeneralSecurityException {
		return true;
	}
}
