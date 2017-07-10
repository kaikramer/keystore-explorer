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
package net.sf.keystore_explorer.crypto.privatekey;

import static net.sf.keystore_explorer.crypto.filetype.CryptoFileType.ENC_PKCS8_PVK;
import static net.sf.keystore_explorer.crypto.filetype.CryptoFileType.UNENC_PKCS8_PVK;
import static net.sf.keystore_explorer.crypto.privatekey.Pkcs8PbeType.SHA1_128BIT_RC4;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.TestCaseKey;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileUtil;
import net.sf.keystore_explorer.crypto.privatekey.Pkcs8PbeType;
import net.sf.keystore_explorer.crypto.privatekey.Pkcs8Util;
import net.sf.keystore_explorer.crypto.privatekey.PrivateKeyEncryptedException;
import net.sf.keystore_explorer.crypto.privatekey.PrivateKeyUnencryptedException;

import org.junit.Test;

/**
 * Unit tests for Pkcs8Util. Encodes RSA And DSA private keys using PKCS #8 and
 * reads it back using a variety of options.
 *
 */
public class TestCasePkcs8Util extends TestCaseKey {
	public TestCasePkcs8Util() throws CryptoException {
		super();
	}

	@Test
	public void unencryptedPkcs8() throws Exception {
		{
			byte[] key = Pkcs8Util.get(rsaPrivateKey);
			assertEquals(rsaPrivateKey, Pkcs8Util.load(new ByteArrayInputStream(key)));
			assertEquals(UNENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}

		{
			byte[] key = Pkcs8Util.get(dsaPrivateKey);
			assertEquals(dsaPrivateKey, Pkcs8Util.load(new ByteArrayInputStream(key)));
			assertEquals(UNENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}
	}

	@Test
	public void unencryptedPkcs8Pem() throws Exception {
		{
			String pemKey = Pkcs8Util.getPem(rsaPrivateKey);
			assertEquals(rsaPrivateKey, Pkcs8Util.load(new ByteArrayInputStream(pemKey.getBytes())));
			assertEquals(UNENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(pemKey.getBytes())));
		}

		{
			String pemKey = Pkcs8Util.getPem(dsaPrivateKey);
			assertEquals(dsaPrivateKey, Pkcs8Util.load(new ByteArrayInputStream(pemKey.getBytes())));
			assertEquals(UNENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(pemKey.getBytes())));
		}
	}

	@Test
	public void encryptedPkcs8() throws Exception {
		for (Pkcs8PbeType pbeType : Pkcs8PbeType.values()) {
			{
				byte[] encKey = Pkcs8Util.getEncrypted(rsaPrivateKey, pbeType, PASSWORD);
				assertEquals(rsaPrivateKey, Pkcs8Util.loadEncrypted(new ByteArrayInputStream(encKey), PASSWORD));
				assertEquals(ENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey)));
			}

			{
				byte[] encKey = Pkcs8Util.getEncrypted(dsaPrivateKey, pbeType, PASSWORD);
				assertEquals(dsaPrivateKey, Pkcs8Util.loadEncrypted(new ByteArrayInputStream(encKey), PASSWORD));
				assertEquals(ENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey)));
			}
		}
	}

	@Test
	public void encryptedPkcs8Pem() throws Exception {
		for (Pkcs8PbeType pbeType : Pkcs8PbeType.values()) {
			{
				String encPemKey = Pkcs8Util.getEncryptedPem(rsaPrivateKey, pbeType, PASSWORD);
				assertEquals(rsaPrivateKey,
						Pkcs8Util.loadEncrypted(new ByteArrayInputStream(encPemKey.getBytes()), PASSWORD));
				assertEquals(ENC_PKCS8_PVK,
						CryptoFileUtil.detectFileType(new ByteArrayInputStream(encPemKey.getBytes())));
			}

			{
				String encPemKey = Pkcs8Util.getEncryptedPem(dsaPrivateKey, pbeType, PASSWORD);
				assertEquals(dsaPrivateKey,
						Pkcs8Util.loadEncrypted(new ByteArrayInputStream(encPemKey.getBytes()), PASSWORD));
				assertEquals(ENC_PKCS8_PVK,
						CryptoFileUtil.detectFileType(new ByteArrayInputStream(encPemKey.getBytes())));
			}
		}
	}

	@Test
	public void incorrectLoadTypeDetected() throws Exception {
		{
			byte[] key = Pkcs8Util.get(rsaPrivateKey);
			assertEquals(UNENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));

			try {
				Pkcs8Util.loadEncrypted(new ByteArrayInputStream(key), PASSWORD);
				fail("Load encrypted for unencrypted PKCS #8 succeeded");
			} catch (PrivateKeyUnencryptedException ex) {
			}
		}

		{
			byte[] key = Pkcs8Util.getEncrypted(rsaPrivateKey, SHA1_128BIT_RC4, PASSWORD);
			assertEquals(ENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));

			try {
				Pkcs8Util.load(new ByteArrayInputStream(key));
				fail("Load unencrypted for encrypted PKCS #8 succeeded");
			} catch (PrivateKeyEncryptedException ex) {
			}
		}
	}
}
