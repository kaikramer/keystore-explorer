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
package org.kse.crypto.csr.spkac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.kse.crypto.KeyPairTestsBase;
import org.kse.crypto.signing.SignatureType;

/**
 * Unit tests for SPKAC.
 *
 */
public class SpkacTest extends KeyPairTestsBase {
	private static final String CHALLENGE = "hello";
	private static final String FALSE_CHALLENGE = "goodbye";
	private static final SpkacSubject SUBJECT = new SpkacSubject("Wayne Grant", "Development", "Lazgo Software",
			"Maddiston", "Falkirk", "GB");

	@ParameterizedTest
	@CsvSource({
		"SPKAC=blah,blah,blah",
		"CN=blah,blah,blah",
	})
	public void invalidVersion(String spkac) {
		assertThrows(SpkacMissingPropertyException.class, () -> new Spkac(new ByteArrayInputStream(spkac.getBytes())));
	}

	@ParameterizedTest
	@CsvSource({
		"MD2_RSA",
		"MD5_RSA",
		"RIPEMD128_RSA",
		"RIPEMD160_RSA",
		"RIPEMD256_RSA",
		"SHA1_RSA",
		"SHA224_RSA",
		"SHA256_RSA",
		"SHA384_RSA",
		"SHA512_RSA",
		"SHA1_DSA",
		"SHA224_DSA",
		"SHA256_DSA",
	})
	public void ripemd160RsaSpkac(SignatureType signatureAlgorithm) throws Exception {

		if (signatureAlgorithm.name().endsWith("_RSA")) {
			doTestSpkac(rsaKeyPair, signatureAlgorithm);
		} else {
			doTestSpkac(dsaKeyPair, signatureAlgorithm);
		}
	}

	private void doTestSpkac(KeyPair keyPair, SignatureType signatureAlgorithm) throws Exception {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		Spkac spkac = new Spkac(CHALLENGE, signatureAlgorithm, SUBJECT, publicKey, privateKey);

		assertEquals(CHALLENGE, spkac.getChallenge());
		assertEquals(signatureAlgorithm, spkac.getSignatureAlgorithm());
		assertEquals(SUBJECT, spkac.getSubject());
		assertEquals(publicKey, spkac.getPublicKey());
		assertEquals(publicKey.getAlgorithm(), spkac.getPublicKeyAlg().jce());

		assertTrue(spkac.verify());
		assertTrue(spkac.verify(CHALLENGE));
		assertFalse(spkac.verify(FALSE_CHALLENGE));

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		spkac.output(baos);

		spkac = new Spkac(new ByteArrayInputStream(baos.toByteArray()));

		assertEquals(CHALLENGE, spkac.getChallenge());
		assertEquals(signatureAlgorithm, spkac.getSignatureAlgorithm());
		assertEquals(SUBJECT, spkac.getSubject());
		assertEquals(publicKey, spkac.getPublicKey());
		assertEquals(publicKey.getAlgorithm(), spkac.getPublicKeyAlg().jce());

		assertTrue(spkac.verify());
		assertTrue(spkac.verify(CHALLENGE));
		assertFalse(spkac.verify(FALSE_CHALLENGE));
	}
}
