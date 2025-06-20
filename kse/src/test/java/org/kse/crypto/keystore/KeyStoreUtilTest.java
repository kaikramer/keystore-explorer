/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.security.KeyStore;
import java.security.Provider;
import java.util.Arrays;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.passwordmanager.Password;
import org.kse.crypto.filetype.CryptoFileUtil;

/**
 * Unit tests for KeyStoreUtil. Runs tests to create, save and load a KeyStore
 * of each of the supported types.
 */
public class KeyStoreUtilTest extends CryptoTestsBase {
    private static final Password PASSWORD = new Password(new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' });

    public KeyStoreUtilTest() {
        super();
    }

    @ParameterizedTest
    // @formatter:off
    @CsvSource({
            "JKS",
            "JCEKS",
            "PKCS12",
            "BKS",
            "UBER",
    })
    // @formatter:on
    public void doTests(KeyStoreType keyStoreType) throws Exception {
        KeyStore keyStore = KeyStoreUtil.create(keyStoreType);

        assertThat(keyStore).isNotNull();
        assertThat(keyStore.getType()).isEqualTo(keyStoreType.jce());

        File keyStoreFile = File.createTempFile("keystore", keyStoreType.jce().toLowerCase());
        keyStoreFile.deleteOnExit();

        KeyStoreUtil.save(keyStore, keyStoreFile, PASSWORD);

        assertThat(keyStoreType).isEqualTo(CryptoFileUtil.detectKeyStoreType(keyStoreFile));
        assertThat(keyStoreType.getCryptoFileType()).isEqualTo(CryptoFileUtil.detectFileType(keyStoreFile));

        KeyStoreUtil.load(keyStoreFile, PASSWORD);

        assertThat(keyStore).isNotNull();
        assertThat(keyStore.getType()).isEqualTo(keyStoreType.jce());
    }

    @ParameterizedTest
    @MethodSource(value = "mldsaSupportedKeyStores")
    void shouldHandleMLDSAKeyPairs(KeyStoreType keyStoreType) throws Exception {
        // Arrange
        KeyStore keyStore = KeyStoreUtil.create(keyStoreType);
        String targetKeyStore = KeyPairType.MLDSA44.jce();
        String targetSignatureAlgorithm = SignatureType.MLDSA44.jce();
        // Act
        Provider provider = keyStore.getProvider();
        // Assert
        assertAll("provider should handle services for MLDSA44",
                () -> assertNotNull(
                        provider.getService("KeyPairGenerator", targetKeyStore)
                ),
                () -> assertNotNull(
                        provider.getService("KeyFactory", targetKeyStore)
                ),
                () -> assertNotNull(
                        provider.getService("Signature", targetSignatureAlgorithm)
                )
        );
    }


    @ParameterizedTest
    @MethodSource(value = "mldsaNotSupportedKeyStores")
    void shouldNotLoadMLDSAKeyPairs(KeyStoreType keyStoreType) throws Exception {
        // Arrange
        KeyStore keyStore = KeyStoreUtil.create(keyStoreType);
        String targetKeyStore = KeyPairType.MLDSA44.jce();
        String targetSignatureAlgorithm = SignatureType.MLDSA44.jce();
        // Act
        Provider provider = keyStore.getProvider();
        // Assert
        assertNull(
                provider.getService("KeyPairGenerator", targetKeyStore)
        );

        assertNull(
                provider.getService("Signature", targetSignatureAlgorithm)
        );
    }


    @ParameterizedTest
    @MethodSource(value = "mldsaSupportedKeyStores")
    void isMLDSAKeyPair(KeyStoreType keyStoreType) throws Exception {
        // Arrange
        KeyStore keyStore = KeyStoreUtil.create(keyStoreType);

        File keyStoreFile = File.createTempFile(
                "keystore", keyStoreType.jce().toLowerCase()
        );
        keyStoreFile.deleteOnExit();

        // Act
        KeyStoreUtil.save(keyStore, keyStoreFile, PASSWORD);
        // Assert
        assertThat(keyStoreType)
                .isEqualTo(CryptoFileUtil.detectKeyStoreType(keyStoreFile));
        assertThat(keyStoreType.getCryptoFileType())
                .isEqualTo(CryptoFileUtil.detectFileType(keyStoreFile));

        KeyStoreUtil.load(keyStoreFile, PASSWORD);

        assertThat(keyStore).isNotNull();
        assertThat(keyStore.getType())
                .isEqualTo(keyStoreType.jce());
    }

    private static Stream<KeyStoreType> mldsaSupportedKeyStores() {
        return Arrays.stream(KeyStoreType.values())
                .filter(KeyStoreType::supportMLDSA)
                .filter(KeyStoreType::isFileBased);
    }

    private static Stream<KeyStoreType> mldsaNotSupportedKeyStores() {
        return Arrays.stream(KeyStoreType.values())
                .filter(Predicate.not(KeyStoreType::supportMLDSA))
                .filter(KeyStoreType::isFileBased);
    }
}
