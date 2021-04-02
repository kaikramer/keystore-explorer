/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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
package org.kse.crypto.keystore;

import org.kse.crypto.CryptoException;

/**
 * Thrown when a KeyStore load fails.
 *
 */
public class KeyStoreLoadException extends CryptoException {
	private static final long serialVersionUID = 1L;
	private KeyStoreType keyStoreType;

	/**
	 * Creates a new KeyStoreLoadException.
	 *
	 * @param keyStoreType
	 *            KeyStore type load was attempted for
	 */
	public KeyStoreLoadException(KeyStoreType keyStoreType) {
		super();

		this.keyStoreType = keyStoreType;
	}

	/**
	 * Creates a new KeyStoreLoadException with the specified message.
	 *
	 * @param message
	 *            Exception message
	 * @param keyStoreType
	 *            KeyStore type load was attempted for
	 */
	public KeyStoreLoadException(String message, KeyStoreType keyStoreType) {
		super(message);

		this.keyStoreType = keyStoreType;
	}

	/**
	 * Creates a new KeyStoreLoadException with the specified message and cause
	 * throwable.
	 *
	 * @param message
	 *            Exception message
	 * @param causeThrowable
	 *            The throwable that caused this exception to be thrown
	 * @param keyStoreType
	 *            KeyStore type load was attempted for
	 */
	public KeyStoreLoadException(String message, Throwable causeThrowable, KeyStoreType keyStoreType) {
		super(message, causeThrowable);

		this.keyStoreType = keyStoreType;
	}

	/**
	 * Creates a new KeyStoreLoadException with the specified cause throwable.
	 *
	 * @param causeThrowable
	 *            The throwable that caused this exception to be thrown
	 * @param keyStoreType
	 *            KeyStore type load was attempted for
	 */
	public KeyStoreLoadException(Throwable causeThrowable, KeyStoreType keyStoreType) {
		super(causeThrowable);

		this.keyStoreType = keyStoreType;
	}

	/**
	 * Get KeyStore type load was attempted for.
	 *
	 * @return KeyStore type
	 */
	public KeyStoreType getKeyStoreType() {
		return keyStoreType;
	}
}
