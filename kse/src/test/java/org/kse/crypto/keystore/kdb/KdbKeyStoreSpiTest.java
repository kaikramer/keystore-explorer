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
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.keystore.kdb.stash.StashFile;

/**
 * Tests the CMS key database KeyStore SPI via the standard java.security.KeyStore API.
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
        X509Certificate cert = TestCertificates.selfSigned("CN=Test", keyPair, 365, "SHA256withRSA");

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
        X509Certificate cert = TestCertificates.selfSigned("CN=Test", keyPair, 365, "SHA256withRSA");

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
    void reEncryptingKeyEntriesChangesTheKeyPassword() throws Exception {
        // Mirrors how SetPasswordAction changes a KDB key store password: each key pair entry is
        // re-encrypted with the new password (serialize() does not re-encrypt keys on its own).
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        X509Certificate cert = TestCertificates.selfSigned("CN=Test", keyPair, 365, "SHA256withRSA");

        char[] oldPassword = "old".toCharArray();
        char[] newPassword = "new".toCharArray();

        KeyStore keyStore = newKdbKeyStore();
        keyStore.setKeyEntry("key", keyPair.getPrivate(), oldPassword, new Certificate[] { cert });

        Key key = keyStore.getKey("key", oldPassword);
        keyStore.setKeyEntry("key", key, newPassword, keyStore.getCertificateChain("key"));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, newPassword);

        KeyStore reloaded = KeyStore.getInstance("KDB", "KSE");
        reloaded.load(new ByteArrayInputStream(out.toByteArray()), newPassword);

        assertThat(reloaded.getKey("key", newPassword)).isEqualTo(keyPair.getPrivate());
        assertThrows(UnrecoverableKeyException.class, () -> reloaded.getKey("key", oldPassword));
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

    // ---------------------------------------------------------------------------------------------
    // Compatibility with populated key databases produced by the native GSKit tooling. The fixtures
    // in testdata/KdbKeyStoreSpiTest were generated with gskcapicmd:
    //   mixed.kdb   - RSA key pair, EC (P-256) key pair, and two trusted CA certificates
    //   chained.kdb - a server key pair plus its issuing intermediate and root CA certificates
    // Both use the key store password "password" and have a sidecar stash (.sth) file.
    // ---------------------------------------------------------------------------------------------

    private static final String NATIVE_DIR = "src/test/resources/testdata/KdbKeyStoreSpiTest";

    private static KeyStore loadNative(String fileName, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("KDB", "KSE");
        try (FileInputStream in = new FileInputStream(new File(NATIVE_DIR, fileName))) {
            keyStore.load(in, password);
        }
        return keyStore;
    }

    @Test
    void readsEntryStructureOfNativeKdb() throws Exception {
        KeyStore keyStore = loadNative("mixed.kdb", PASSWORD);

        assertThat(Collections.list(keyStore.aliases()))
                .containsExactlyInAnyOrder("rsa-keypair", "ec-keypair",
                                           "trusted-root-ca", "trusted-intermediate-ca");

        assertThat(keyStore.isKeyEntry("rsa-keypair")).isTrue();
        assertThat(keyStore.isKeyEntry("ec-keypair")).isTrue();
        assertThat(keyStore.isCertificateEntry("rsa-keypair")).isFalse();

        assertThat(keyStore.isCertificateEntry("trusted-root-ca")).isTrue();
        assertThat(keyStore.isCertificateEntry("trusted-intermediate-ca")).isTrue();
        assertThat(keyStore.isKeyEntry("trusted-root-ca")).isFalse();
    }

    @Test
    void recoversRsaKeyPairFromNativeKdb() throws Exception {
        KeyStore keyStore = loadNative("mixed.kdb", PASSWORD);

        Key key = keyStore.getKey("rsa-keypair", PASSWORD);
        assertThat(key).isInstanceOf(PrivateKey.class);
        assertThat(key.getAlgorithm()).isEqualTo("RSA");

        X509Certificate cert = (X509Certificate) keyStore.getCertificate("rsa-keypair");
        assertThat(cert.getPublicKey()).isInstanceOf(RSAPublicKey.class);
        assertThat(((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength()).isEqualTo(2048);
        // A self-signed key pair has a single-element certificate chain
        assertThat(keyStore.getCertificateChain("rsa-keypair")).hasSize(1);
    }

    @Test
    void recoversEcKeyPairFromNativeKdb() throws Exception {
        KeyStore keyStore = loadNative("mixed.kdb", PASSWORD);

        Key key = keyStore.getKey("ec-keypair", PASSWORD);
        assertThat(key).isInstanceOf(PrivateKey.class);
        assertThat(key.getAlgorithm()).isEqualTo("EC");

        X509Certificate cert = (X509Certificate) keyStore.getCertificate("ec-keypair");
        assertThat(cert.getPublicKey()).isInstanceOf(ECPublicKey.class);
        assertThat(((ECPublicKey) cert.getPublicKey()).getParams().getCurve().getField().getFieldSize())
                .isEqualTo(256);
    }

    @Test
    void trustedCaEntriesHaveNoPrivateKey() throws Exception {
        KeyStore keyStore = loadNative("mixed.kdb", PASSWORD);

        assertThat(keyStore.getKey("trusted-root-ca", PASSWORD)).isNull();

        X509Certificate root = (X509Certificate) keyStore.getCertificate("trusted-root-ca");
        assertThat(root.getSubjectX500Principal().getName()).contains("Example Root CA");
        // A CA certificate carries basic constraints (getBasicConstraints() != -1)
        assertThat(root.getBasicConstraints()).isNotEqualTo(-1);
    }

    @Test
    void wrongPasswordFailsToRecoverNativeKey() throws Exception {
        KeyStore keyStore = loadNative("mixed.kdb", PASSWORD);

        assertThrows(UnrecoverableKeyException.class,
                     () -> keyStore.getKey("rsa-keypair", "wrong".toCharArray()));
    }

    @Test
    void readsCertificateChainLinkageFromNativeKdb() throws Exception {
        KeyStore keyStore = loadNative("chained.kdb", PASSWORD);

        assertThat(Collections.list(keyStore.aliases()))
                .containsExactlyInAnyOrder("server-cert", "intermediate-ca", "root-ca");

        X509Certificate leaf = (X509Certificate) keyStore.getCertificate("server-cert");
        X509Certificate intermediate = (X509Certificate) keyStore.getCertificate("intermediate-ca");
        X509Certificate root = (X509Certificate) keyStore.getCertificate("root-ca");

        // Issuer/subject linkage proves the certificates were parsed correctly: leaf <- intermediate <- root
        assertThat(leaf.getIssuerX500Principal()).isEqualTo(intermediate.getSubjectX500Principal());
        assertThat(intermediate.getIssuerX500Principal()).isEqualTo(root.getSubjectX500Principal());
        assertThat(root.getIssuerX500Principal()).isEqualTo(root.getSubjectX500Principal());

        assertThat(keyStore.isKeyEntry("server-cert")).isTrue();
        assertThat(keyStore.getKey("server-cert", PASSWORD)).isInstanceOf(PrivateKey.class);
    }

    @Test
    void nativeKdbCanBeEditedAndResaved() throws Exception {
        KeyStore keyStore = loadNative("mixed.kdb", PASSWORD);

        // Edit the key store loaded from native tooling, then round-trip it through KSE
        X509Certificate root = (X509Certificate) keyStore.getCertificate("trusted-root-ca");
        keyStore.setCertificateEntry("added-ca", root);
        keyStore.deleteEntry("ec-keypair");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, PASSWORD);

        KeyStore reloaded = KeyStore.getInstance("KDB", "KSE");
        reloaded.load(new ByteArrayInputStream(out.toByteArray()), PASSWORD);

        assertThat(Collections.list(reloaded.aliases()))
                .containsExactlyInAnyOrder("rsa-keypair", "trusted-root-ca",
                                           "trusted-intermediate-ca", "added-ca");
        assertThat(reloaded.getKey("rsa-keypair", PASSWORD)).isInstanceOf(PrivateKey.class);
    }

    @Test
    void loadsNativeKdbUsingPasswordFromStash() throws Exception {
        String password = StashFile.decodeFile(new File(NATIVE_DIR, "mixed.sth").toPath());
        assertThat(password).isEqualTo("password");

        KeyStore keyStore = loadNative("mixed.kdb", password.toCharArray());
        assertThat(keyStore.getKey("ec-keypair", password.toCharArray())).isInstanceOf(PrivateKey.class);
    }
}
