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
package org.kse.crypto.keystore.kdb;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.kse.crypto.CryptoTestsBase;

/**
 * Tests the IBM CMS key database KeyStore SPI via the standard java.security.KeyStore API.
 */
class KdbKeyStoreSpiTest extends CryptoTestsBase {

    private static final char[] PASSWORD = "password".toCharArray();

    private static KeyStore newKdbKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("KDB", "KSE");
        keyStore.load(null, null);
        return keyStore;
    }

    @Test
    void getInstanceInitializesViaKseProvider() throws Exception {
        KeyStore keyStore = newKdbKeyStore();

        assertThat(keyStore.getType()).isEqualTo("KDB");
        assertThat(keyStore.getProvider().getName()).isEqualTo("KSE");
        assertThat(keyStore.size()).isZero();
    }

    @Test
    void entriesRoundTripThroughStoreAndLoad() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        X509Certificate cert = X509Builder.selfSigned("CN=Test", keyPair, 365, "SHA256withRSA");

        KeyStore keyStore = newKdbKeyStore();
        keyStore.setKeyEntry("key", keyPair.getPrivate(), PASSWORD, new Certificate[] { cert });
        keyStore.setCertificateEntry("trusted", cert);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, PASSWORD);

        KeyStore reloaded = KeyStore.getInstance("KDB", "KSE");
        reloaded.load(new ByteArrayInputStream(out.toByteArray()), PASSWORD);

        List<String> aliases = Collections.list(reloaded.aliases());
        assertThat(aliases).containsExactlyInAnyOrder("key", "trusted");

        assertThat(reloaded.isKeyEntry("key")).isTrue();
        assertThat(reloaded.isCertificateEntry("trusted")).isTrue();

        Key key = reloaded.getKey("key", PASSWORD);
        assertThat(key).isEqualTo(keyPair.getPrivate());
        assertThat(reloaded.getCertificate("key")).isEqualTo(cert);
        assertThat(reloaded.getCertificateChain("key")).containsExactly(cert);
        assertThat(reloaded.getCertificateAlias(cert)).isEqualTo("key");

        reloaded.deleteEntry("trusted");
        assertThat(reloaded.size()).isEqualTo(1);
    }

    @Test
    void storeAndLoadWithEmptyPassword() throws Exception {
        // KeyStoreUtil.copy() round-trips keystores through store/load with an empty password
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        X509Certificate cert = X509Builder.selfSigned("CN=Test", keyPair, 365, "SHA256withRSA");

        KeyStore keyStore = newKdbKeyStore();
        keyStore.setKeyEntry("key", keyPair.getPrivate(), PASSWORD, new Certificate[] { cert });
        keyStore.setCertificateEntry("trusted", cert);

        char[] emptyPassword = {};
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, emptyPassword);

        KeyStore reloaded = KeyStore.getInstance("KDB", "KSE");
        reloaded.load(new ByteArrayInputStream(out.toByteArray()), emptyPassword);

        assertThat(Collections.list(reloaded.aliases())).containsExactlyInAnyOrder("key", "trusted");
        // key entries keep their original encryption password through the copy
        assertThat(reloaded.getKey("key", PASSWORD)).isEqualTo(keyPair.getPrivate());
    }

    @Test
    void loadingWithWrongPasswordFails() throws Exception {
        KeyStore keyStore = newKdbKeyStore();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, PASSWORD);

        KeyStore reloaded = KeyStore.getInstance("KDB", "KSE");
        assertThrows(IOException.class,
                     () -> reloaded.load(new ByteArrayInputStream(out.toByteArray()), "wrong".toCharArray()));
    }

    @Test
    void loadsKdbCreatedByNativeTooling() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("KDB", "KSE");
        File kdbFile = new File("src/test/resources/testdata/CryptoFileUtilTest", "keystore.kdb");

        try (FileInputStream in = new FileInputStream(kdbFile)) {
            keyStore.load(in, PASSWORD);
        }

        assertThat(keyStore.size()).isZero();
    }
}
