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

package org.kse.utilities.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.of;

import java.io.File;
import java.net.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class PacProxySelectorTest {

    private static final String TEST_FILES_PATH = "test/testdata/PacProxySelectorTest";

    @BeforeEach
    void setUp() {
        // execute all tests with a fixed "current" date and time (note: the 7. of August 2022 was a Sunday)
        PacHelperFunctions.setClock(Clock.fixed(Instant.parse("2022-08-07T07:00:00Z"), ZoneOffset.of("+00:00")));
    }

    @ParameterizedTest
    @MethodSource
    void select(String pacFile, String[] expectedProxyList) throws URISyntaxException {
        File pacFile1 = new File(TEST_FILES_PATH, pacFile);

        PacProxySelector selector = new PacProxySelector(pacFile1.toURI());
        List<Proxy> proxyList = selector.select(new URI("http://www.example.net"));

        assertThat(proxyList).extracting((proxy) -> proxy.toString().replaceAll("/<unresolved>", ""))
                             .containsExactlyInAnyOrder(expectedProxyList);
    }

    private static Stream<Arguments> select() {
        return Stream.of(
                of("pac1.js", new String[] { "HTTP @ proxy.example.com:8080", "DIRECT" }),
                of("pac2.js", new String[] { "HTTP @ /4.5.6.7:8080", "HTTP @ /7.8.9.10:8080" }),
                of("pac3.js", new String[] { "HTTP @ wcg1.example.com:8080" })
        );
    }

    @ParameterizedTest
    @MethodSource
    void selectWithSandboxedCode(String pacFile) throws URISyntaxException {
        File file = new File(TEST_FILES_PATH, pacFile);

        PacProxySelector selector = new PacProxySelector(file.toURI());
        assertThat(selector.select(new URI("http://www.example.net"))).containsOnly(Proxy.NO_PROXY);
    }

    private static Stream<Arguments> selectWithSandboxedCode() {
        return Stream.of(
                of("pac_sandbox1.js"),
                of("pac_sandbox2.js")
        );
    }
}