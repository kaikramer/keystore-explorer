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
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.kse.crypto.filetype.CryptoFileType.ENC_PKCS8_PVK;
import static org.kse.crypto.filetype.CryptoFileType.UNENC_PKCS8_PVK;
import static org.kse.crypto.privatekey.Pkcs8PbeType.SHA1_128BIT_RC4;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.kse.crypto.KeyTestsBase;
import org.kse.crypto.filetype.CryptoFileUtil;

/**
 * Unit tests for Pkcs8Util. Encodes RSA And DSA private keys using PKCS #8 and
 * reads it back using a variety of options.
 *
 */
public class Pkcs8UtilTest extends KeyTestsBase {

	@ParameterizedTest
	@MethodSource("privateKeys")
	public void unencryptedPkcs8(PrivateKey privateKey) throws Exception {
		byte[] key = Pkcs8Util.get(privateKey);
		assertEquals(privateKey, Pkcs8Util.load(new ByteArrayInputStream(key)));
		assertEquals(UNENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
	}

	@ParameterizedTest
	@MethodSource("privateKeys")
	public void unencryptedPkcs8Pem(PrivateKey privateKey) throws Exception {
		String pemKey = Pkcs8Util.getPem(privateKey);
		assertEquals(privateKey, Pkcs8Util.load(new ByteArrayInputStream(pemKey.getBytes())));
		assertEquals(UNENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(pemKey.getBytes())));
	}

	@TestFactory
	Iterable<DynamicTest> testAllPbeTypes() throws Exception {
		List<DynamicTest> tests = new ArrayList<>();

		for (PrivateKey privateKey : privateKeys()) {
			for (Pkcs8PbeType pbeType : Pkcs8PbeType.values()) {
				tests.add(dynamicTest("test " + pbeType.name() + "/" + privateKey.getClass().getSimpleName(), () -> {
					byte[] encKey = Pkcs8Util.getEncrypted(privateKey, pbeType, PASSWORD);
					assertEquals(privateKey, Pkcs8Util.loadEncrypted(new ByteArrayInputStream(encKey), PASSWORD));
					assertEquals(ENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey)));
				}));
			}
		}
		return tests;
	}

	@TestFactory
	Iterable<DynamicTest> testAllPbeTypesPem() throws Exception {
		List<DynamicTest> tests = new ArrayList<>();

		for (PrivateKey privateKey : privateKeys()) {
			for (Pkcs8PbeType pbeType : Pkcs8PbeType.values()) {
				tests.add(dynamicTest("test " + pbeType.name() + "/" + privateKey.getClass().getSimpleName(), () -> {
					byte[] encKey = Pkcs8Util.getEncryptedPem(privateKey, pbeType, PASSWORD).getBytes();
					assertEquals(privateKey, Pkcs8Util.loadEncrypted(new ByteArrayInputStream(encKey), PASSWORD));
					assertEquals(ENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey)));
				}));
			}
		}
		return tests;
	}

	@Test
	public void incorrectLoadTypeDetected() throws Exception {
		byte[] key = Pkcs8Util.get(rsaPrivateKey);
		assertEquals(UNENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		assertThrows(PrivateKeyUnencryptedException.class,
				() -> Pkcs8Util.loadEncrypted(new ByteArrayInputStream(key), PASSWORD));

		byte[] encKey = Pkcs8Util.getEncrypted(rsaPrivateKey, SHA1_128BIT_RC4, PASSWORD);
		assertEquals(ENC_PKCS8_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey)));
		assertThrows(PrivateKeyEncryptedException.class, () -> Pkcs8Util.load(new ByteArrayInputStream(encKey)));
	}
}
