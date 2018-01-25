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
import static org.kse.crypto.filetype.CryptoFileType.ENC_OPENSSL_PVK;
import static org.kse.crypto.filetype.CryptoFileType.UNENC_OPENSSL_PVK;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.kse.crypto.KeyTestsBase;
import org.kse.crypto.filetype.CryptoFileUtil;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for OpenSslPvkUtil. Encodes a RSA, EC and DSA private keys using
 * OpenSSL format and reads them back using a variety of options.
 *
 */
public class OpenSslPvkUtilTest extends KeyTestsBase {

	@ParameterizedTest
	@MethodSource("privateKeys")
	public void unencryptedOpenSslPvk(PrivateKey privateKey) throws Exception {
		byte[] key = OpenSslPvkUtil.get(privateKey);
		assertEquals(privateKey, OpenSslPvkUtil.load(new ByteArrayInputStream(key)));
		assertEquals(UNENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
	}

	@ParameterizedTest
	@MethodSource("privateKeys")
	public void unencryptedOpenSslPvkPem(PrivateKey privateKey) throws Exception {
		String pemKey = OpenSslPvkUtil.getPem(privateKey);
		assertEquals(privateKey, OpenSslPvkUtil.load(new ByteArrayInputStream(pemKey.getBytes())));
		assertEquals(UNENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(pemKey.getBytes())));
	}

	@TestFactory
	Iterable<DynamicTest> testAllPbeTypes() throws Exception {
		List<DynamicTest> tests = new ArrayList<>();
		for (PrivateKey privateKey : privateKeys()) {
			for (OpenSslPbeType pbeType : OpenSslPbeType.values()) {
				tests.add(dynamicTest("test " + pbeType.name() + "/" + privateKey.getClass().getSimpleName(), () -> {
					byte[] encKey = OpenSslPvkUtil.getEncrypted(privateKey, pbeType, PASSWORD).getBytes();
					assertEquals(privateKey, OpenSslPvkUtil.loadEncrypted(new ByteArrayInputStream(encKey), PASSWORD));
					assertEquals(ENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey)));
				}));
			}
		}
		return tests;
	}

	@ParameterizedTest
	@MethodSource("privateKeys")
	public void checkCompatibilityWithBC(PrivateKey privateKey) throws Exception {
		String key = OpenSslPvkUtil.getPem(privateKey);
		try (PEMParser pemParser = new PEMParser(new StringReader(key))) {
			Object obj = pemParser.readObject();
			assertThat(obj).isInstanceOf(PEMKeyPair.class);
			KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) obj);
			assertThat(keyPair.getPrivate()).isEqualTo(privateKey);
		}
	}

	@Test
	public void incorrectLoadTypeDetected() throws Exception {
		byte[] key = OpenSslPvkUtil.get(rsaPrivateKey);
		assertEquals(UNENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(key)));
		assertThrows(PrivateKeyUnencryptedException.class,
				() -> OpenSslPvkUtil.loadEncrypted(new ByteArrayInputStream(key), PASSWORD));

		String encKey = OpenSslPvkUtil.getEncrypted(rsaPrivateKey, OpenSslPbeType.DESEDE_CBC, PASSWORD);
		assertEquals(ENC_OPENSSL_PVK, CryptoFileUtil.detectFileType(new ByteArrayInputStream(encKey.getBytes())));
		assertThrows(PrivateKeyEncryptedException.class,
				() -> OpenSslPvkUtil.load(new ByteArrayInputStream(encKey.getBytes())));
	}
}
