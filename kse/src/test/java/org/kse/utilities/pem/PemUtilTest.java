/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

package org.kse.utilities.pem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Unit tests for PemUtil.
 */
public class PemUtilTest {

    private static final String TEST_FILES_PATH = "src/test/resources/testdata/PemUtilTest";

    @Test
    void decodeAll() throws IOException {
        // keystore.pem contains several malformed entries that are skipped
        byte[] data = Files.readAllBytes(new File(TEST_FILES_PATH, "keystore.pem").toPath());

        String[] expectedTypes = {
                // @formatter:off
                "PRIVATE KEY",
                "CERTIFICATE",
                "PRIVATE KEY",
                "CERTIFICATE",
                "PRIVATE KEY",
                "CERTIFICATE",
                "CERTIFICATE",
                "PRIVATE KEY",
                "CERTIFICATE",
                "PRIVATE KEY",
                "CERTIFICATE",
                "CERTIFICATE",
                "PRIVATE KEY",
                "CERTIFICATE",
                "CERTIFICATE",
                "CERTIFICATE",
                "PRIVATE KEY",
                "CERTIFICATE",
                "CERTIFICATE",
                "CERTIFICATE",
                "CERTIFICATE",
                "CERTIFICATE",
              // @formatter:on
        };

        List<PemInfo> blocks = PemUtil.decodeAll(data);
        assertEquals(expectedTypes.length, blocks.size());
        for (int i = 0; i < expectedTypes.length; ++i) {
            assertEquals(expectedTypes[i], blocks.get(i).getType(), "Index: " + i);
        }
    }

    @ParameterizedTest
    // @formatter:off
    @CsvSource({
        "single-key-rsa.pem, PRIVATE KEY, false",
        "single-key-ec.pem, EC PRIVATE KEY, false",
        "single-key-cert.pem, PRIVATE KEY, false",
        "rsa-encrypted.pem, RSA PRIVATE KEY, true",
        "rsa-plain.pem, RSA PRIVATE KEY, false",
    })
    // @formatter:on
    void decodePem(String fileName, String expectedType, boolean expectedAttributes) throws IOException {
        byte[] data = Files.readAllBytes(new File(TEST_FILES_PATH, fileName).toPath());

        PemInfo pem = PemUtil.decode(data);
        assertEquals(expectedType, pem.getType());
        assertEquals(expectedAttributes, pem.getAttributes() != null);
    }

    @ParameterizedTest
    // @formatter:off
    @CsvSource({
        "bad-key-attributes.pem",
        "bad-key-binary.pem",
        "bad-key-malformed.pem",
        "bad-key-mismatch.pem",
    })
    // @formatter:on
    void decodeNonPem(String fileName) throws IOException {
        byte[] data = Files.readAllBytes(new File(TEST_FILES_PATH, fileName).toPath());

        assertNull(PemUtil.decode(data));
    }

    @Test
    void decodeAttributes() throws IOException {
        byte[] data = Files.readAllBytes(new File(TEST_FILES_PATH, "rsa-encrypted.pem").toPath());

        PemInfo pem = PemUtil.decode(data);
        assertNotNull(pem.getAttributes());
        assertEquals(2, pem.getAttributes().size());
        assertEquals("Proc-Type", pem.getAttributes().get("Proc-Type").getName());
        assertEquals("4,ENCRYPTED", pem.getAttributes().get("Proc-Type").getValue());
        assertEquals("DEK-Info", pem.getAttributes().get("DEK-Info").getName());
        assertEquals("AES-128-CBC,7F17F3AB6BB7C4DC88041C98CFA6A3D2", pem.getAttributes().get("DEK-Info").getValue());
    }

}
