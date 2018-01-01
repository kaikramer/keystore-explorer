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
package org.kse.crypto.publickey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.kse.crypto.filetype.CryptoFileType.OPENSSL_PUB;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.kse.crypto.KeyTestsBase;
import org.kse.crypto.filetype.CryptoFileUtil;

/**
 * Unit tests for OpenSslPubUtil. Encodes a RSA and DSA private keys using
 * OpenSSL format and reads them back using a variety of options.
 *
 */
public class OpenSslPubUtilTest extends KeyTestsBase {

	@ParameterizedTest
	@MethodSource("publicKeys")
	public void openSslPub(PublicKey publicKey) throws Exception {
		byte[] key = OpenSslPubUtil.get(publicKey);
		assertEquals(publicKey, OpenSslPubUtil.load(new ByteArrayInputStream(key)));
		assertEquals(OPENSSL_PUB, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
	}

	@ParameterizedTest
	@MethodSource("publicKeys")
	public void openSslPubPem(PublicKey publicKey) throws Exception {
		String pemKey = OpenSslPubUtil.getPem(publicKey);
		assertEquals(publicKey, OpenSslPubUtil.load(new ByteArrayInputStream(pemKey.getBytes())));
		assertEquals(OPENSSL_PUB, CryptoFileUtil.detectFileType(new ByteArrayInputStream(pemKey.getBytes())));
	}
}
