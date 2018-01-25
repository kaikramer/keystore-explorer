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
package org.kse.crypto.keystore;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.Password;
import org.kse.crypto.filetype.CryptoFileUtil;

/**
 * Unit tests for KeyStoreUtil. Runs tests to create, save and load a KeyStore
 * of each of the supported types.
 *
 */
public class KeyStoreUtilTest extends CryptoTestsBase {
	private static final Password PASSWORD = new Password(new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' });

	public KeyStoreUtilTest() {
		super();
	}

	@ParameterizedTest
	@CsvSource({
		"JKS",
		"JCEKS",
		"PKCS12",
		"BKS",
		"BKS_V1",
		"UBER",
	})
	public void doTests(KeyStoreType keyStoreType) throws Exception {
		KeyStore keyStore = KeyStoreUtil.create(keyStoreType);

		assertThat(keyStore).isNotNull();
		assertThat(keyStore.getType()).isEqualTo(keyStoreType.jce());

		File keyStoreFile = File.createTempFile("keystore", null);
		keyStoreFile.deleteOnExit();

		KeyStoreUtil.save(keyStore, keyStoreFile, PASSWORD);

		assertThat(keyStoreType).isEqualTo(CryptoFileUtil.detectKeyStoreType(new FileInputStream(keyStoreFile)));
		assertThat(keyStoreType.getCryptoFileType()).isEqualTo(CryptoFileUtil.detectFileType(new FileInputStream(keyStoreFile)));

		KeyStoreUtil.load(keyStoreFile, PASSWORD);

		assertThat(keyStore).isNotNull();
		assertThat(keyStore.getType()).isEqualTo(keyStoreType.jce());
	}
}
