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
import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.keystore_explorer.crypto.KeyInfo;
import net.sf.keystore_explorer.crypto.TestCaseCrypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import static net.sf.keystore_explorer.crypto.keypair.KeyPairType.DSA;
import static net.sf.keystore_explorer.crypto.keypair.KeyPairType.RSA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for KeyPairUtil. Runs a test to create a key pair for supported
 * types and a selection of key sizes.
 *
 */
public class TestCaseKeyPairUtil extends TestCaseCrypto {
	public TestCaseKeyPairUtil() {
		super();
	}

	@Test
	public void dsa512() throws Exception {
		doTest(DSA, 512);
	}

	@Test
	public void dsa1024() throws Exception {
		doTest(DSA, 1024);
	}

	@Test
	public void rsa512() throws Exception {
		doTest(RSA, 512);
	}

	@Test
	public void rsa1024() throws Exception {
		doTest(RSA, 1024);
	}

	@Test
	public void rsa2048() throws Exception {
		doTest(RSA, 2048);
	}

	private void doTest(KeyPairType keyPairType, Integer keySize) throws Exception {
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
