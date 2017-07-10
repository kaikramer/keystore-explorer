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

import static net.sf.keystore_explorer.crypto.filetype.CryptoFileType.ENC_OPENSSL_PVK;
import static net.sf.keystore_explorer.crypto.filetype.CryptoFileType.UNENC_OPENSSL_PVK;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.TestCaseKey;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileUtil;
import net.sf.keystore_explorer.crypto.privatekey.OpenSslPbeType;
import net.sf.keystore_explorer.crypto.privatekey.OpenSslPvkUtil;
import net.sf.keystore_explorer.crypto.privatekey.PrivateKeyEncryptedException;
import net.sf.keystore_explorer.crypto.privatekey.PrivateKeyUnencryptedException;

import org.junit.Test;

/**
 * Unit tests for OpenSslPvkUtil. Encodes a RSA and DSA private keys using
 * OpenSSL format and reads them back using a variety of options.
 *
 */
public class TestCaseOpenSslPvkUtil extends TestCaseKey {
	public TestCaseOpenSslPvkUtil() throws CryptoException {
		super();
	}

	@Test
	public void unencryptedOpenSslPvk() throws Exception {
		{
			byte[] key = OpenSslPvkUtil.get(rsaPrivateKey);
			assertEquals(rsaPrivateKey, OpenSslPvkUtil.load(new ByteArrayInputStream(key)));
			assertEquals(UNENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}

		{
			byte[] key = OpenSslPvkUtil.get(dsaPrivateKey);
			assertEquals(dsaPrivateKey, OpenSslPvkUtil.load(new ByteArrayInputStream(key)));
			assertEquals(UNENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}
	}

	@Test
	public void unencryptedOpenSslPvkPem() throws Exception {
		{
			String pemKey = OpenSslPvkUtil.getPem(rsaPrivateKey);
			assertEquals(rsaPrivateKey, OpenSslPvkUtil.load(new ByteArrayInputStream(pemKey.getBytes())));
			assertEquals(UNENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(pemKey.getBytes())));
		}

		{
			String pemKey = OpenSslPvkUtil.getPem(dsaPrivateKey);
			assertEquals(dsaPrivateKey, OpenSslPvkUtil.load(new ByteArrayInputStream(pemKey.getBytes())));
			assertEquals(UNENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(pemKey.getBytes())));
		}
	}

	@Test
	public void encryptedOpenSslPvk() throws Exception {
		for (OpenSslPbeType pbeType : OpenSslPbeType.values()) {
			{
				String encKey = OpenSslPvkUtil.getEncrypted(rsaPrivateKey, pbeType, PASSWORD);
				assertEquals(rsaPrivateKey,
						OpenSslPvkUtil.loadEncrypted(new ByteArrayInputStream(encKey.getBytes()), PASSWORD));
				assertEquals(ENC_OPENSSL_PVK,
						CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey.getBytes())));
			}

			{
				String encKey = OpenSslPvkUtil.getEncrypted(dsaPrivateKey, pbeType, PASSWORD);
				assertEquals(dsaPrivateKey,
						OpenSslPvkUtil.loadEncrypted(new ByteArrayInputStream(encKey.getBytes()), PASSWORD));
				assertEquals(ENC_OPENSSL_PVK,
						CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey.getBytes())));
			}
		}
	}

	@Test
	public void incorrectLoadTypeDetected() throws Exception {
		{
			byte[] key = OpenSslPvkUtil.get(rsaPrivateKey);
			assertEquals(UNENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));

			try {
				OpenSslPvkUtil.loadEncrypted(new ByteArrayInputStream(key), PASSWORD);
				fail("Load encrypted for unencrypted OpenSSL succeeded");
			} catch (PrivateKeyUnencryptedException ex) {
			}
		}

		{
			String encKey = OpenSslPvkUtil.getEncrypted(rsaPrivateKey, OpenSslPbeType.DESEDE_CBC, PASSWORD);
			assertEquals(ENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey.getBytes())));

			try {
				OpenSslPvkUtil.load(new ByteArrayInputStream(encKey.getBytes()));
				fail("Load unencrypted for encrypted OpenSSL succeeded");
			} catch (PrivateKeyEncryptedException ex) {
			}
		}
	}
}
