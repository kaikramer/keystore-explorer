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
package org.kse.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;

/**
 * Abstract base class for all private or public key test cases.
 *
 */
public abstract class TestCaseKey extends TestCaseCrypto {
	protected static final Password PASSWORD = new Password(new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' });
	protected static RSAPrivateCrtKey rsaPrivateKey;
	protected static RSAPublicKey rsaPublicKey;
	protected static DSAPrivateKey dsaPrivateKey;
	protected static DSAPublicKey dsaPublicKey;

	public static List<PrivateKey> privateKeys() {
		return Arrays.asList(rsaPrivateKey, dsaPrivateKey);
	}

	public static List<PublicKey> publicKeys() {
		return Arrays.asList(rsaPublicKey, dsaPublicKey);
	}

	@BeforeAll
	public static void initKeys() throws CryptoException {

		if (rsaPrivateKey == null) {
			KeyPair rsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 1024, new BouncyCastleProvider());
			rsaPrivateKey = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
			rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
		}

		if (dsaPrivateKey == null) {
			KeyPair dsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.DSA, 1024, new BouncyCastleProvider());
			dsaPrivateKey = (DSAPrivateKey) dsaKeyPair.getPrivate();
			dsaPublicKey = (DSAPublicKey) dsaKeyPair.getPublic();
		}
	}

}
