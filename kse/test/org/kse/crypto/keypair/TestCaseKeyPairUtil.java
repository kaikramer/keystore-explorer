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
package org.kse.crypto.keypair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.TestCaseCrypto;

/**
 * Unit tests for KeyPairUtil. Runs a test to create a key pair for supported
 * types and a selection of key sizes.
 *
 */
public class TestCaseKeyPairUtil extends TestCaseCrypto {
	public TestCaseKeyPairUtil() {
		super();
	}

	@ParameterizedTest
	@CsvSource({
		"DSA, 512",
		"DSA, 1024",
		"RSA, 512",
		"RSA, 1024",
		"RSA, 2048",
		"RSA, 3072",
		//"RSA, 4096", takes too long
	})
	public void doTests(KeyPairType keyPairType, Integer keySize) throws Exception {
		KeyPair keyPair = KeyPairUtil.generateKeyPair(keyPairType, keySize, new BouncyCastleProvider());

		PrivateKey privateKey = keyPair.getPrivate();
		KeyInfo privateKeyInfo = KeyPairUtil.getKeyInfo(privateKey);
		assertEquals(keyPairType.toString(), privateKeyInfo.getAlgorithm());
		assertEquals(keySize, privateKeyInfo.getSize());

		PublicKey publicKey = keyPair.getPublic();
		KeyInfo publicKeyInfo = KeyPairUtil.getKeyInfo(publicKey);
		assertEquals(keyPairType.toString(), publicKeyInfo.getAlgorithm());
		assertEquals(keySize, publicKeyInfo.getSize());

		assertTrue(KeyPairUtil.validKeyPair(privateKey, publicKey));
	}
}
