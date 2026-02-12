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
package org.kse.crypto.keystore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.filetype.CryptoFileUtil;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X509CertificateGenerator;
import org.kse.crypto.x509.X509CertificateVersion;
import org.kse.gui.passwordmanager.Password;

/**
 * Unit tests for KeyStoreUtil. Runs tests to create, save and load a KeyStore
 * of each of the supported types.
 */
public class KeyStoreUtilTest extends CryptoTestsBase {
    private static final Password PASSWORD = new Password(new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' });

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
    void doTests(KeyStoreType keyStoreType) throws Exception {
        KseKeyStore keyStore = KeyStoreUtil.create(keyStoreType);

        assertThat(keyStore).isNotNull();
        assertThat(keyStore.getType()).isEqualTo(keyStoreType.jce());

        File keyStoreFile = File.createTempFile("keystore", keyStoreType.jce().toLowerCase());
        keyStoreFile.deleteOnExit();

        KeyStoreUtil.save(keyStore, keyStoreFile, PASSWORD);

        assertThat(keyStoreType).isEqualTo(CryptoFileUtil.detectKeyStoreType(keyStoreFile));
        assertThat(keyStoreType.getCryptoFileType()).isEqualTo(CryptoFileUtil.detectFileType(keyStoreFile));

        keyStore = KeyStoreUtil.load(keyStoreFile, PASSWORD);

        assertThat(keyStore).isNotNull();
        assertThat(keyStore.getType()).isEqualTo(keyStoreType.jce());
    }

    @ParameterizedTest
    @MethodSource(value = "fileBasedKeyStores")
    void isMLDSAKeyPair(KeyStoreType keyStoreType) throws Exception {
        // Arrange
        KseKeyStore keyStore = KeyStoreUtil.create(keyStoreType);

        File keyStoreFile = File.createTempFile(
                "keystore", keyStoreType.jce().toLowerCase()
        );
        keyStoreFile.deleteOnExit();

        KeyPair keyPair = KeyPairUtil.generateKeyPair(KeyPairType.MLDSA44, KSE.BC);
        X509Certificate cert = generateCert(keyPair, SignatureType.MLDSA44);

        // Act
        keyStore.setKeyEntry("alias", keyPair.getPrivate(), PASSWORD.toCharArray(), new Certificate[] {cert});
        KeyStoreUtil.save(keyStore, keyStoreFile, PASSWORD);

        // Assert
        assertThat(keyStoreType)
                .isEqualTo(CryptoFileUtil.detectKeyStoreType(keyStoreFile));
        assertThat(keyStoreType.getCryptoFileType())
                .isEqualTo(CryptoFileUtil.detectFileType(keyStoreFile));

        keyStore = KeyStoreUtil.load(keyStoreFile, PASSWORD);

        assertThat(keyStore).isNotNull();
        assertThat(keyStore.getType()).isEqualTo(keyStoreType.jce());
        assertNotNull(keyStore.getKey("alias", PASSWORD.toCharArray()));
    }

    @ParameterizedTest
    @MethodSource(value = "fileBasedKeyStores")
    void isSlhDsaKeyPair(KeyStoreType keyStoreType) throws Exception {
        KseKeyStore keyStore = KeyStoreUtil.create(keyStoreType);
        File keyStoreFile = File.createTempFile("keystore", keyStoreType.jce().toLowerCase());
        keyStoreFile.deleteOnExit();

        KeyPair keyPair = KeyPairUtil.generateKeyPair(KeyPairType.SLHDSA_SHA2_128F, KSE.BC);
        X509Certificate cert = generateCert(keyPair, SignatureType.SLHDSA);

        keyStore.setKeyEntry("alias", keyPair.getPrivate(), PASSWORD.toCharArray(), new Certificate[] {cert});
        KeyStoreUtil.save(keyStore, keyStoreFile, PASSWORD);

        assertThat(keyStoreType).isEqualTo(CryptoFileUtil.detectKeyStoreType(keyStoreFile));
        assertThat(keyStoreType.getCryptoFileType()).isEqualTo(CryptoFileUtil.detectFileType(keyStoreFile));

        keyStore = KeyStoreUtil.load(keyStoreFile, PASSWORD);

        assertThat(keyStore).isNotNull();
        assertThat(keyStore.getType()).isEqualTo(keyStoreType.jce());
        assertNotNull(keyStore.getKey("alias", PASSWORD.toCharArray()));
    }

    private X509Certificate generateCert(KeyPair keyPair, SignatureType signatureType) throws CryptoException {
        X509CertificateGenerator certGen = new X509CertificateGenerator(X509CertificateVersion.VERSION3);
        X509Certificate cert = certGen.generateSelfSigned(new X500Name("cn=Cert"), Date.from(Instant.now()),
                                                            Date.from(Instant.now().plus(3650, ChronoUnit.DAYS)),
                                                            keyPair.getPublic(), keyPair.getPrivate(),
                                                            signatureType, new BigInteger(
                        Hex.decode("1122334455667788990011223344556677889900")));
        return cert;
    }

    private static Stream<KeyStoreType> fileBasedKeyStores() {
        return Arrays.stream(KeyStoreType.values())
                .filter(KeyStoreType::isFileBased);
    }

}
