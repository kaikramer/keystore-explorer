/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
package net.sf.keystore_explorer.crypto.keypair;

import java.security.KeyPair;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.TestCaseCrypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Abstract base class for all key pair test cases. Sets up test key pairs.
 *
 */
public abstract class TestCaseKeyPair extends TestCaseCrypto {
	protected static KeyPair rsaKeyPair;
	protected static KeyPair dsaKeyPair;

	public TestCaseKeyPair() throws CryptoException {
		super();

		if (rsaKeyPair == null) {
			rsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 2048, new BouncyCastleProvider());
		}

		if (dsaKeyPair == null) {
			dsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.DSA, 1024, new BouncyCastleProvider());
		}
	}
}
