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
package org.kse.crypto;

import java.security.KeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;

/**
 * Abstract base class for all key pair test cases. Sets up test key pairs.
 *
 */
public abstract class KeyPairTestsBase extends CryptoTestsBase {
	protected static KeyPair rsaKeyPair;
	protected static KeyPair dsaKeyPair;

	@BeforeAll
	public static void initKeyPairs() throws CryptoException {

		if (rsaKeyPair == null) {
			rsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 2048, BC);
		}

		if (dsaKeyPair == null) {
			dsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.DSA, 1024, BC);
		}
	}
}
