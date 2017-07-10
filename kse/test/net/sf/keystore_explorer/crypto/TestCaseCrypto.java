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


package net.sf.keystore_explorer.crypto;

import static org.junit.Assert.fail;

import java.security.Provider;
import java.security.Security;

/**
 * Abstract base class for all test cases. Sets up the BC provider.
 *
 */
public abstract class TestCaseCrypto {
	public TestCaseCrypto() {
		addBcProvider();
	}

	private void addBcProvider() {
		try {
			Class bcProvClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
			Provider bcProv = (Provider) bcProvClass.newInstance();
			Security.addProvider(bcProv);
		} catch (Throwable thw) {
			fail("Could not instantiate BC provider");
		}
	}

}
