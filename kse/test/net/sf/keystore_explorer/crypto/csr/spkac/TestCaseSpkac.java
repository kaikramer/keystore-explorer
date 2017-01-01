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
package net.sf.keystore_explorer.crypto.csr.spkac;

import static net.sf.keystore_explorer.crypto.signing.SignatureType.MD2_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.MD5_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA1_DSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA1_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA224_DSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA224_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA256_DSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA256_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA384_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA512_RSA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.csr.spkac.Spkac;
import net.sf.keystore_explorer.crypto.csr.spkac.SpkacMissingPropertyException;
import net.sf.keystore_explorer.crypto.csr.spkac.SpkacSubject;
import net.sf.keystore_explorer.crypto.keypair.TestCaseKeyPair;
import net.sf.keystore_explorer.crypto.signing.SignatureType;

import org.junit.Test;

/**
 * Unit tests for SPKAC.
 *
 */
public class TestCaseSpkac extends TestCaseKeyPair {
	private static final String CHALLENGE = "hello";
	private static final String FALSE_CHALLENGE = "goodbye";
	private static final SpkacSubject SUBJECT = new SpkacSubject("Wayne Grant", "Development", "Lazgo Software",
			"Maddiston", "Falkirk", "GB");

	public TestCaseSpkac() throws CryptoException {
		super();
	}

	@Test
	public void loadSpkacWithNoSubjectPropertiesFails() throws Exception {
		String spkacWithNoSubjectText = "SPKAC=blah,blah,blah";

		try {
			new Spkac(new ByteArrayInputStream(spkacWithNoSubjectText.getBytes()));
			fail("Did not throw SpkacMissingPropertyException for spkac with no subject properties");
		} catch (SpkacMissingPropertyException ex) {
		}
	}

	@Test
	public void loadSpkacWithNoSpkacPropertyFails() throws Exception {
		String spkacWithNoSubjectText = "CN=blah,blah,blah";

		try {
			new Spkac(new ByteArrayInputStream(spkacWithNoSubjectText.getBytes()));
			fail("Did not throw SpkacMissingPropertyException for spkac with no SPKAC property");
		} catch (SpkacMissingPropertyException ex) {
		}
	}

	@Test
	public void md2RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, MD2_RSA);
	}

	@Test
	public void md5RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, MD5_RSA);
	}

	@Test
	public void ripemd128RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, SignatureType.RIPEMD128_RSA);
	}

	@Test
	public void ripemd160RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, SignatureType.RIPEMD160_RSA);
	}

	@Test
	public void ripemd256RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, SignatureType.RIPEMD256_RSA);
	}

	@Test
	public void sha1RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, SHA1_RSA);
	}

	@Test
	public void sha224RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, SHA224_RSA);
	}

	@Test
	public void sha256RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, SHA256_RSA);
	}

	@Test
	public void sha384RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, SHA384_RSA);
	}

	@Test
	public void sha512RsaSpkac() throws Exception {
		doTestSpkac(rsaKeyPair, SHA512_RSA);
	}

	@Test
	public void sha1DsaSpkac() throws Exception {
		doTestSpkac(dsaKeyPair, SHA1_DSA);
	}

	@Test
	public void sha224DsaSpkac() throws Exception {
		doTestSpkac(dsaKeyPair, SHA224_DSA);
	}

	@Test
	public void sha256DsaSpkac() throws Exception {
		doTestSpkac(dsaKeyPair, SHA256_DSA);
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
