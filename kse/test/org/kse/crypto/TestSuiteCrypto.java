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
package org.kse.crypto;

import junit.framework.TestSuite;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.kse.crypto.csr.spkac.TestCaseSpkac;
import org.kse.crypto.digest.TestCaseDigestUtil;
import org.kse.crypto.keypair.TestCaseKeyPairUtil;
import org.kse.crypto.keystore.TestCaseKeyStoreUtil;
import org.kse.crypto.privatekey.TestCaseOpenSslPvkUtil;
import org.kse.crypto.privatekey.TestCasePkcs8Util;
import org.kse.crypto.privatekey.TestCasePvkUtil;
import org.kse.crypto.publickey.TestCaseOpenSslPubUtil;

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
