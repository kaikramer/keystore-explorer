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
package org.kse.crypto.keypair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.KeyInfo;

/**
 * Unit tests for KeyPairUtil. Runs a test to create a key pair for supported
 * types and a selection of key sizes.
 *
 */
public class KeyPairUtilTest extends CryptoTestsBase {

	@ParameterizedTest
	@CsvSource({
		"DSA, 512",
		"DSA, 1024",
		"RSA, 512",
		"RSA, 1024",
		"RSA, 2048",
		//"RSA, 3072", takes too long
		//"RSA, 4096", takes too long
	})
	public void generateRsaDsaKeys(KeyPairType keyPairType, Integer keySize) throws Exception {
		KeyPair keyPair = KeyPairUtil.generateKeyPair(keyPairType, keySize, BC);

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

	@ParameterizedTest
	@ValueSource(strings = {
		// NIST curves
		"B-163", "B-233", "B-283", "B-409", "B-571", "K-163", "K-233", "K-283", "K-409", "K-571", "P-192", "P-224",
		"P-256", "P-384", "P-521",
		// SEC curves
		"secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2", "secp192k1",
		"secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1", "sect113r1",
		"sect113r2", "sect131r1", "sect131r2", "sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2",
		"sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1",
		"sect571r1",
		// ANSI X9.62 curves
		"prime192v1", "prime192v2", "prime192v3", "prime239v1", "prime239v2", "prime239v3", "prime256v1", "c2pnb163v1",
		"c2pnb163v2", "c2pnb163v3", "c2pnb176w1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3", "c2tnb239v1", "c2tnb239v2",
		"c2tnb239v3", "c2tnb359v1", "c2tnb431r1", "c2pnb208w1", "c2pnb272w1", "c2pnb304w1", "c2pnb368w1",
		// Brainpool curves
		"brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1", "brainpoolP192t1", "brainpoolP224r1", "brainpoolP224t1",
		"brainpoolP256r1", "brainpoolP256t1", "brainpoolP320r1", "brainpoolP320t1", "brainpoolP384r1", "brainpoolP384t1",
		"brainpoolP512r1", "brainpoolP512t1"
	})
	public void generateEcKeys(String curveName) throws Exception {
		KeyPair keyPair = KeyPairUtil.generateECKeyPair(curveName, BC);
		assertTrue(KeyPairUtil.validKeyPair(keyPair.getPrivate(), keyPair.getPublic()));
	}
}
