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

import junit.framework.TestSuite;
import net.sf.keystore_explorer.crypto.csr.spkac.TestCaseSpkac;
import net.sf.keystore_explorer.crypto.digest.TestCaseDigestUtil;
import net.sf.keystore_explorer.crypto.keypair.TestCaseKeyPairUtil;
import net.sf.keystore_explorer.crypto.keystore.TestCaseKeyStoreUtil;
import net.sf.keystore_explorer.crypto.privatekey.TestCaseOpenSslPvkUtil;
import net.sf.keystore_explorer.crypto.privatekey.TestCasePkcs8Util;
import net.sf.keystore_explorer.crypto.privatekey.TestCasePvkUtil;
import net.sf.keystore_explorer.crypto.publickey.TestCaseOpenSslPubUtil;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * Unit tests for crypto package.
 *
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ TestCaseKeyStoreUtil.class, TestCaseDigestUtil.class, TestCaseKeyPairUtil.class,
	TestCasePkcs8Util.class, TestCasePvkUtil.class, TestCaseOpenSslPvkUtil.class, TestCaseOpenSslPubUtil.class,
	TestCaseSpkac.class })
public class TestSuiteCrypto extends TestSuite {

}
