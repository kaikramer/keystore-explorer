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
import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.DSAPrivateKey;
import java.util.HashMap;
import java.util.ResourceBundle;

import org.bouncycastle.jce.provider.JDKDSAPrivateKey;
import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;

/**
 * Records a single state for a KeyStore in the undo/redo history. This includes
 * a cache of both the KeyStore and its entries' passwords.
 *
 */
public class KeyStoreState {
	/** Resource bundle */
	protected static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/utilities/history/resources");

	private KeyStoreHistory history;
	HistoryAction action;
	private KeyStore keyStore;
	private Password password;
	private HashMap<String, Password> entryPasswords = new HashMap<String, Password>();
	private KeyStoreState previous;
	private KeyStoreState next;

	/**
	 * Create an empty state.
	 */
	KeyStoreState() {
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
	KeyStoreState(KeyStoreHistory history, KeyStore keyStore, Password password) {
		this.history = history;
		this.keyStore = keyStore;
		this.password = password;
	}

	/**
	 * Append a state subsequently to this one and set it to be the current
	 * state.
	 *
	 * @param keyStoreState
	 *            State
	 */
	public void append(KeyStoreState keyStoreState) {
		keyStoreState.previous = this;
		this.next = keyStoreState;
		keyStoreState.setAsCurrentState();
	}

	/**
	 * Get the desciption of the action that created this state.
	 *
	 * @return Description or null if none
	 */
	public String getActionDescription() {
		if (action != null) {
			return action.getHistoryDescription();
		}

		return null;
	}

	/**
	 * Set this state to be the current state in the history.
	 */
	public void setAsCurrentState() {
		history.setCurrentState(this);
	}

	/**
	 * Is this state the initial state in the history?
	 *
	 * @return True if it is
	 */
	public boolean isInitialState() {
		return this == history.getInitialState();
	}

	/**
	 * Is this state the saved state in the history?
	 *
	 * @return True if it is
	 */
	public boolean isSavedState() {
		return this == history.getSavedState();
	}

	/**
	 * Set this state to be the saved state in the history.
	 */
	public void setAsSavedState() {
		history.setSavedState(this);
	}

	/**
	 * Set the previous state as the current state if it exists.
	 *
	 * @throws CryptoException
	 *             If entry passwords could not be propogated to new state
	 */
	public void setPreviousStateAsCurrentState() throws CryptoException {
		if (previous != null) {
			propagateNewPasswords(previous);
			previous.setAsCurrentState();
		}
	}

	/**
	 * Set the next state as the current state if it exists.
	 *
	 * @throws CryptoException
	 *             If entry passwords could not be propogated to new state
	 */
	public void setNextStateAsCurrentState() throws CryptoException {
		if (next != null) {
			propagateNewPasswords(next);
			next.setAsCurrentState();
		}
	}

	/**
	 * Is there a previous state?
	 *
	 * @return True if there is
	 */
	public boolean hasPreviousState() {
		return previous != null;
	}

	/**
	 * Get previous state.
	 *
	 * @return Previous state or null if none
	 */
	public KeyStoreState previousState() {
		return previous;
	}

	/**
	 * Is there a next state?
	 *
	 * @return True if there is
	 */
	public boolean hasNextState() {
		return next != null;
	}

	/**
	 * Get next state.
	 *
	 * @return Next state or null if none
	 */
	public KeyStoreState nextState() {
		return next;
	}

	/**
	 * Get KeyStore's type.
	 *
	 * @return KeyStore's type
	 */
	public KeyStoreType getType() {
		return KeyStoreType.resolveJce(keyStore.getType());
	}

	/**
	 * Get the KeyStore.
	 *
	 * @return The KeyStore
	 */
	public KeyStore getKeyStore() {
		return keyStore;
	}

	/**
	 * Set the KeyStore.
	 *
	 * @param keyStore
	 *            The KeyStore
	 */
	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}

	/**
	 * Get the cached KeyStore password
	 *
	 * @return Password
	 */
	public Password getPassword() {
		return password;
	}

	/**
	 * Set the cached KeyStore password.
	 *
	 * @param password
	 *            Password
	 */
	public void setPassword(Password password) {
		this.password = password;
	}

	/**
	 * Set the cached password for a particular entry.
	 *
	 * @param alias
	 *            The entry's alias
	 * @param password
	 *            The entry's cached password
	 */
	public void setEntryPassword(String alias, Password password) {
		entryPasswords.put(alias, password);
	}

	/**
	 * Remove a particular entry's cached password.
	 *
	 * @param alias
	 *            The entry's alias
	 */
	public void removeEntryPassword(String alias) {
		Password removedPassword = entryPasswords.remove(alias);

		if (removedPassword != null) {
			removedPassword.nullPassword();
		}
	}

	/**
	 * Get the cached password for a particular entry.
	 *
	 * @param alias
	 *            The entry's alias
	 * @return The entry's password or null if none is set
	 */
	public Password getEntryPassword(String alias) {
		return entryPasswords.get(alias);
	}

	/**
	 * Null all passwords contained in the state.
	 */
	public void nullPasswords() {
		// Null KeyStore password if present
		if (password != null) {
			password.nullPassword();
		}

		// Null all entry passwords
		for (String alias : entryPasswords.keySet()) {
			entryPasswords.get(alias).nullPassword();
		}
	}

	/**
	 * Create the basis for the next state based on this one. Makes a copy of
	 * the current state excluding its position in the history.
	 *
	 * @param action
	 *            The action responsible for the creation of the next state
	 * @return Next state
	 * @throws CryptoException
	 *             If underlying KeyStore could not be copied
	 */
	public KeyStoreState createBasisForNextState(HistoryAction action) throws CryptoException {
		KeyStoreState copy = new KeyStoreState();
		copy.history = this.history;
		copy.keyStore = KeyStoreUtil.copy(this.keyStore);

		if (this.password != null) {
			copy.password = new Password(this.password); // Copy as may be cleared
		}

		HashMap<String, Password> keyPairPasswordsCopy = new HashMap<String, Password>();

		for (String alias : entryPasswords.keySet()) {
			keyPairPasswordsCopy.put(alias, new Password(entryPasswords.get(alias)));
		}

		copy.entryPasswords = keyPairPasswordsCopy;

		copy.action = action;

		return copy;
	}

	protected void propagateNewPasswords(KeyStoreState targetState) throws CryptoException {

		// Copy all entry passwords not found in the target state from the current state to the target state
		try {
			for (String alias : entryPasswords.keySet()) {
				if (KeyStoreUtil.isKeyPairEntry(alias, targetState.keyStore)) {
					if (!targetState.entryPasswords.containsKey(alias)) {
						Password newPassword = entryPasswords.get(alias);

						if (isPasswordPropagationValid(targetState, alias, newPassword)) {
							targetState.setEntryPassword(alias, newPassword);
						}
					}
				}
			}
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoPropagateEntryPasswords.exception.message"), ex);
		}
	}

	protected boolean isPasswordPropagationValid(KeyStoreState targetState, String alias, Password password)
			throws GeneralSecurityException {
		// A password should only be propagated to a target state if it is correct and represents the same private key
		// as the current state
		return isEntryPasswordCorrect(targetState, alias, password)
				&& isEntryPrivateKeyEqual(targetState, alias, password);
	}

	protected boolean isEntryPasswordCorrect(KeyStoreState targetState, String alias, Password password) {
		try {
			targetState.keyStore.getKey(alias, password.toCharArray());

			return true;
		} catch (GeneralSecurityException ex) {
			return false; // Could not retrieve key part of key pair using password
		}
	}

	protected boolean isEntryPrivateKeyEqual(KeyStoreState targetState, String alias, Password password)
			throws GeneralSecurityException {
		Key currentKey = keyStore.getKey(alias, password.toCharArray());
		Key targetKey = targetState.getKeyStore().getKey(alias, password.toCharArray());

		// JDKDSAPrivateKey has no equals method defined
		if ((currentKey instanceof JDKDSAPrivateKey) || (targetKey instanceof JDKDSAPrivateKey)) {
			DSAPrivateKey currentDsaKey = (DSAPrivateKey) currentKey;
			DSAPrivateKey targetDsaKey = (DSAPrivateKey) targetKey;

			return currentDsaKey.getX().equals(targetDsaKey.getX())
					&& currentDsaKey.getParams().getG().equals(targetDsaKey.getParams().getG())
					&& currentDsaKey.getParams().getP().equals(targetDsaKey.getParams().getP())
					&& currentDsaKey.getParams().getQ().equals(targetDsaKey.getParams().getQ());
		} else {
			return currentKey.equals(targetKey);
		}
	}


}
