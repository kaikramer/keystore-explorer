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
package net.sf.keystore_explorer.crypto.digest;

import static net.sf.keystore_explorer.crypto.digest.DigestType.MD2;
import static net.sf.keystore_explorer.crypto.digest.DigestType.MD4;
import static net.sf.keystore_explorer.crypto.digest.DigestType.MD5;
import static net.sf.keystore_explorer.crypto.digest.DigestType.RIPEMD128;
import static net.sf.keystore_explorer.crypto.digest.DigestType.RIPEMD160;
import static net.sf.keystore_explorer.crypto.digest.DigestType.RIPEMD256;
import static net.sf.keystore_explorer.crypto.digest.DigestType.SHA1;
import static net.sf.keystore_explorer.crypto.digest.DigestType.SHA224;
import static net.sf.keystore_explorer.crypto.digest.DigestType.SHA256;
import static net.sf.keystore_explorer.crypto.digest.DigestType.SHA384;
import static net.sf.keystore_explorer.crypto.digest.DigestType.SHA512;
import static org.junit.Assert.assertTrue;
import net.sf.keystore_explorer.crypto.TestCaseCrypto;
import net.sf.keystore_explorer.crypto.digest.DigestType;
import net.sf.keystore_explorer.crypto.digest.DigestUtil;

import org.junit.Test;

/**
 * Unit tests for DigestUtil. Runs tests to create a digest for each of the
 * supported types.
 *
 */
public class TestCaseDigestUtil extends TestCaseCrypto {
	private String MESSAGE = "This is a really good test message honestly";

	@Test
	public void md2() throws Exception {
		doTest(MD2);
	}

	@Test
	public void md4() throws Exception {
		doTest(MD4);
	}

	@Test
	public void md5() throws Exception {
		doTest(MD5);
	}

	@Test
	public void sha1() throws Exception {
		doTest(SHA1);
	}

	@Test
	public void sha224() throws Exception {
		doTest(SHA224);
	}

	@Test
	public void sha256() throws Exception {
		doTest(SHA256);
	}

	@Test
	public void sha384() throws Exception {
		doTest(SHA384);
	}

	@Test
	public void sha512() throws Exception {
		doTest(SHA512);
	}

	@Test
	public void ripemd128() throws Exception {
		doTest(RIPEMD128);
	}

	@Test
	public void ripemd160() throws Exception {
		doTest(RIPEMD160);
	}

	@Test
	public void ripemd256() throws Exception {
		doTest(RIPEMD256);
	}

	private void doTest(DigestType digestType) throws Exception {
		String digest = DigestUtil.getFriendlyMessageDigest(MESSAGE.getBytes(), digestType);

		assertTrue(!digest.equals(MESSAGE));
	}
}
