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
package net.sf.keystore_explorer.crypto.keystore;

import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.BKS;
import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.JCEKS;
import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.JKS;
import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.PKCS12;
import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.UBER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

import net.sf.keystore_explorer.crypto.Password;
import net.sf.keystore_explorer.crypto.TestCaseCrypto;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileUtil;
import net.sf.keystore_explorer.crypto.keystore.KeyStoreType;
import net.sf.keystore_explorer.crypto.keystore.KeyStoreUtil;

import org.junit.Test;

/**
 * Unit tests for KeyStoreUtil. Runs tests to create, save and load a KeyStore
 * of each of the supported types.
 *
 */
public class TestCaseKeyStoreUtil extends TestCaseCrypto {
	private static final Password PASSWORD = new Password(new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' });

	public TestCaseKeyStoreUtil() {
		super();
	}

	@Test
	public void jks() throws Exception {
		doTest(JKS);
	}

	@Test
	public void jceks() throws Exception {
		doTest(JCEKS);
	}

	@Test
	public void pkcs12() throws Exception {
		doTest(PKCS12);
	}

	@Test
	public void bks() throws Exception {
		doTest(BKS);
	}

	@Test
	public void uber() throws Exception {
		doTest(UBER);
	}

	private void doTest(KeyStoreType keyStoreType) throws Exception {
		KeyStore keyStore = KeyStoreUtil.create(keyStoreType);

		assertNotNull(keyStore);
		assertEquals(keyStore.getType(), keyStoreType.jce());

		File keyStoreFile = File.createTempFile("keystore", null);
		keyStoreFile.deleteOnExit();

		KeyStoreUtil.save(keyStore, keyStoreFile, PASSWORD);

		assertEquals(keyStoreType, CryptoFileUtil.detectKeyStoreType(new FileInputStream(keyStoreFile)));
		assertEquals(keyStoreType.getCryptoFileType(), CryptoFileUtil.detectFileType(new FileInputStream(keyStoreFile)));

		KeyStoreUtil.load(keyStoreFile, PASSWORD);

		assertNotNull(keyStore);
		assertEquals(keyStore.getType(), keyStoreType.jce());
	}
}
