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
package org.kse.utilities.buffer;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.kse.crypto.Password;

/**
 * Key pair buffer entry.
 *
 */
public class KeyPairBufferEntry extends BufferEntry {
	private PrivateKey privateKey;
	private Certificate[] certificateChain;
	private Password password;

	/**
	 * Construct.
	 *
	 * @param name
	 *            Entry name
	 * @param cut
	 *            Is entry to be cut?
	 * @param privateKey
	 *            Private key
	 * @param password
	 *            Key pair password
	 * @param certificateChain
	 *            Certificate chain
	 */
	public KeyPairBufferEntry(String name, boolean cut, PrivateKey privateKey, Password password,
			Certificate[] certificateChain) {
		super(name, cut);

		this.privateKey = privateKey;
		this.certificateChain = certificateChain;
		this.password = new Password(password); // Copy as may be cleared
	}

	/**
	 * Get private key.
	 *
	 * @return Private key
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Get password.
	 *
	 * @return Password
	 */
	public Password getPassword() {
		return new Password(password); // Copy as may be cleared
	}

	/**
	 * Get certificate chain.
	 *
	 * @return Certificate chain
	 */
	public Certificate[] getCertificateChain() {
		return certificateChain;
	}

	@Override
	void clear() {
		password.nullPassword();
	}
}
