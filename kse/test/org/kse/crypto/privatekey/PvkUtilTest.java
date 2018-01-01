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
package org.kse.crypto.privatekey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.kse.crypto.filetype.CryptoFileType.ENC_MS_PVK;
import static org.kse.crypto.filetype.CryptoFileType.UNENC_MS_PVK;

import java.io.ByteArrayInputStream;

import org.junit.jupiter.api.Test;
import org.kse.crypto.KeyTestsBase;
import org.kse.crypto.filetype.CryptoFileUtil;

/**
 * Unit tests for PvkUtil. Encodes a RSA and DSA private keys using Microsoft's
 * PVK format and reads them back using a variety of options.
 *
 */
public class PvkUtilTest extends KeyTestsBase {

	@Test
	public void unencryptedPvk() throws Exception {
		{
			byte[] key = MsPvkUtil.get(rsaPrivateKey, MsPvkUtil.PVK_KEY_EXCHANGE);
			assertEquals(rsaPrivateKey, MsPvkUtil.load(new ByteArrayInputStream(key)));
			assertEquals(UNENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}

		{
			byte[] key = MsPvkUtil.get(rsaPrivateKey, MsPvkUtil.PVK_KEY_SIGNATURE);
			assertEquals(rsaPrivateKey, MsPvkUtil.load(new ByteArrayInputStream(key)));
			assertEquals(UNENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}

		{
			byte[] key = MsPvkUtil.get(dsaPrivateKey);
			assertEquals(dsaPrivateKey, MsPvkUtil.load(new ByteArrayInputStream(key)));
			assertEquals(UNENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}
	}

	@Test
	public void weakEncryptedPvk() throws Exception {
		{
			byte[] key = MsPvkUtil.getEncrypted(rsaPrivateKey, MsPvkUtil.PVK_KEY_EXCHANGE, PASSWORD, false);
			assertEquals(rsaPrivateKey, MsPvkUtil.loadEncrypted(new ByteArrayInputStream(key), PASSWORD));
			assertEquals(ENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}

		{
			byte[] key = MsPvkUtil.getEncrypted(rsaPrivateKey, MsPvkUtil.PVK_KEY_SIGNATURE, PASSWORD, false);
			assertEquals(rsaPrivateKey, MsPvkUtil.loadEncrypted(new ByteArrayInputStream(key), PASSWORD));
			assertEquals(ENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}

		{
			byte[] key = MsPvkUtil.getEncrypted(dsaPrivateKey, PASSWORD, false);
			assertEquals(dsaPrivateKey, MsPvkUtil.loadEncrypted(new ByteArrayInputStream(key), PASSWORD));
			assertEquals(ENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}
	}

	@Test
	public void strongEncryptedPvk() throws Exception {
		{
			byte[] key = MsPvkUtil.getEncrypted(rsaPrivateKey, MsPvkUtil.PVK_KEY_EXCHANGE, PASSWORD, true);
			assertEquals(rsaPrivateKey, MsPvkUtil.loadEncrypted(new ByteArrayInputStream(key), PASSWORD));
			assertEquals(ENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}

		{
			byte[] key = MsPvkUtil.getEncrypted(rsaPrivateKey, MsPvkUtil.PVK_KEY_SIGNATURE, PASSWORD, true);
			assertEquals(rsaPrivateKey, MsPvkUtil.loadEncrypted(new ByteArrayInputStream(key), PASSWORD));
			assertEquals(ENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}

		{
			byte[] key = MsPvkUtil.getEncrypted(dsaPrivateKey, PASSWORD, false);
			assertEquals(dsaPrivateKey, MsPvkUtil.loadEncrypted(new ByteArrayInputStream(key), PASSWORD));
			assertEquals(ENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}
	}

	@Test
	public void incorrectLoadTypeDetected() throws Exception {
		byte[] key = MsPvkUtil.get(rsaPrivateKey, MsPvkUtil.PVK_KEY_EXCHANGE);
		assertEquals(UNENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		assertThrows(PrivateKeyUnencryptedException.class,
				() -> MsPvkUtil.loadEncrypted(new ByteArrayInputStream(key), PASSWORD));

		byte[] encKey = MsPvkUtil.getEncrypted(rsaPrivateKey, MsPvkUtil.PVK_KEY_EXCHANGE, PASSWORD, true);
		assertEquals(ENC_MS_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey)));
		assertThrows(PrivateKeyEncryptedException.class, () -> MsPvkUtil.load(new ByteArrayInputStream(encKey)));
	}

}
