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
package org.kse.crypto.digest;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.kse.crypto.CryptoTestsBase;

/**
 * Unit tests for DigestUtil. Runs tests to create a digest for each of the supported types.
 *
 */
public class DigestUtilTest extends CryptoTestsBase {
	private String MESSAGE = "This is a really good test message honestly";

	@ParameterizedTest
	@CsvSource({
		"MD2",
		"MD4",
		"MD5",
		"SHA1",
		"SHA224",
		"SHA256",
		"SHA384",
		"SHA512",
		"RIPEMD128",
		"RIPEMD160",
		"RIPEMD256",
	})
	public void testMessageDigests(DigestType digestType) throws Exception {
		String digest = DigestUtil.getFriendlyMessageDigest(MESSAGE.getBytes(), digestType);
		assertThat(digest).isNotEqualTo(MESSAGE);
	}
}
