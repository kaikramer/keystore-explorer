/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

package org.kse.crypto.signing;

import java.io.IOException;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.kse.crypto.digest.DigestType;
import org.kse.utilities.net.URLs;

class TimeStampingClientTest {

    private static final byte[] DATA = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

    @ParameterizedTest
    @MethodSource("tsaUrls")
    public void testTsaUrls(String tsaUrl) throws IOException {
        Assertions.assertThatCode(
                          () -> TimeStampingClient.getTimeStampToken(tsaUrl, DATA, DigestType.SHA256))
                  .doesNotThrowAnyException();
    }

    static String[] tsaUrls() {
        return URLs.TSA_URLS;
    }
}
