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
package net.sf.keystore_explorer.crypto.publickey;

import static net.sf.keystore_explorer.crypto.filetype.CryptoFileType.OPENSSL_PUB;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.TestCaseKey;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileUtil;
import net.sf.keystore_explorer.crypto.publickey.OpenSslPubUtil;

import org.junit.Test;

/**
 * Unit tests for OpenSslPubUtil. Encodes a RSA and DSA private keys using
 * OpenSSL format and reads them back using a variety of options.
 *
 */
public class TestCaseOpenSslPubUtil extends TestCaseKey {
	public TestCaseOpenSslPubUtil() throws CryptoException {
		super();
	}

	@Test
	public void openSslPub() throws Exception {
		{
			byte[] key = OpenSslPubUtil.get(rsaPublicKey);
			assertEquals(rsaPublicKey, OpenSslPubUtil.load(new ByteArrayInputStream(key)));
			assertEquals(OPENSSL_PUB, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}

		{
			byte[] key = OpenSslPubUtil.get(dsaPublicKey);
			assertEquals(dsaPublicKey, OpenSslPubUtil.load(new ByteArrayInputStream(key)));
			assertEquals(OPENSSL_PUB, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		}
	}

	@Test
	public void openSslPubPem() throws Exception {
		{
			String pemKey = OpenSslPubUtil.getPem(rsaPublicKey);
			assertEquals(rsaPublicKey, OpenSslPubUtil.load(new ByteArrayInputStream(pemKey.getBytes())));
			assertEquals(OPENSSL_PUB, CryptoFileUtil.detectFileType(new ByteArrayInputStream(pemKey.getBytes())));
		}

		{
			String pemKey = OpenSslPubUtil.getPem(dsaPublicKey);
			assertEquals(dsaPublicKey, OpenSslPubUtil.load(new ByteArrayInputStream(pemKey.getBytes())));
			assertEquals(OPENSSL_PUB, CryptoFileUtil.detectFileType(new ByteArrayInputStream(pemKey.getBytes())));
		}
	}
}
