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
package org.kse.crypto.keypair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.KeyType;

/**
 * Unit tests for KeyPairUtil. Runs a test to create a key pair for supported
 * types and a selection of key sizes.
 */
public class KeyPairUtilTest extends CryptoTestsBase {

    @ParameterizedTest
    // @formatter:off
    @CsvSource({
            "DSA, 512",
            "DSA, 1024",
            "RSA, 512",
            "RSA, 1024",
            "RSA, 2048",
            //"RSA, 3072", takes too long
            //"RSA, 4096", takes too long
    })
    // @formatter:on
    void generateRsaDsaKeys(KeyPairType keyPairType, Integer keySize) throws Exception {
        KeyPair keyPair = KeyPairUtil.generateKeyPair(keyPairType, keySize, KSE.BC);

        PrivateKey privateKey = keyPair.getPrivate();
        KeyInfo privateKeyInfo = KeyPairUtil.getKeyInfo(privateKey);
        assertEquals(keyPairType.toString(), privateKeyInfo.getAlgorithm());
        assertEquals(keySize, privateKeyInfo.getSize());

        PublicKey publicKey = keyPair.getPublic();
        KeyInfo publicKeyInfo = KeyPairUtil.getKeyInfo(publicKey);
        assertEquals(keyPairType.toString(), publicKeyInfo.getAlgorithm());
        assertEquals(keySize, publicKeyInfo.getSize());

        assertTrue(KeyPairUtil.validKeyPair(privateKey, publicKey));

        KeyInfo privKeyInfo = KeyPairUtil.getKeyInfo(privateKey);
        assertEquals(KeyType.ASYMMETRIC, privKeyInfo.getKeyType());
        assertEquals(keyPairType.jce(), privKeyInfo.getAlgorithm());
        assertEquals(keySize, privKeyInfo.getSize());
        assertEquals("-", privKeyInfo.getDetailedAlgorithm());

        KeyInfo pubKeyInfo = KeyPairUtil.getKeyInfo(publicKey);
        assertEquals(KeyType.ASYMMETRIC, pubKeyInfo.getKeyType());
        assertEquals(keyPairType.jce(), pubKeyInfo.getAlgorithm());
        assertEquals(keySize, pubKeyInfo.getSize());
        assertEquals("-", pubKeyInfo.getDetailedAlgorithm());

        assertEquals(keyPairType, KeyPairUtil.getKeyPairType(privateKey));
        assertEquals(keyPairType, KeyPairUtil.getKeyPairType(publicKey));
    }

    @ParameterizedTest
    // @formatter:off
    @ValueSource(strings = {
            // NIST curves
            "B-163", "B-233", "B-283", "B-409", "B-571", "K-163", "K-233", "K-283", "K-409", "K-571", "P-192", "P-224",
            "P-256", "P-384", "P-521",
            // SEC curves
            "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2", "secp192k1",
            "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1", "sect113r1",
            "sect113r2", "sect131r1", "sect131r2", "sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2",
            "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1",
            "sect571r1",
            // ANSI X9.62 curves
            "prime192v1", "prime192v2", "prime192v3", "prime239v1", "prime239v2", "prime239v3", "prime256v1",
            "c2pnb163v1",
            "c2pnb163v2", "c2pnb163v3", "c2pnb176w1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3", "c2tnb239v1",
            "c2tnb239v2",
            "c2tnb239v3", "c2tnb359v1", "c2tnb431r1", "c2pnb208w1", "c2pnb272w1", "c2pnb304w1", "c2pnb368w1",
            // Brainpool curves
            "brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1", "brainpoolP192t1", "brainpoolP224r1",
            "brainpoolP224t1",
            "brainpoolP256r1", "brainpoolP256t1", "brainpoolP320r1", "brainpoolP320t1", "brainpoolP384r1",
            "brainpoolP384t1",
            "brainpoolP512r1", "brainpoolP512t1",
            // SM2 curves
            "sm2p256v1", "wapi192v1", "wapip192v1"
    })
    // @formatter:on
    void generateEcKeys(String curveName) throws Exception {
        KeyPair keyPair = KeyPairUtil.generateECKeyPair(curveName, KSE.BC);
        assertTrue(KeyPairUtil.validKeyPair(keyPair.getPrivate(), keyPair.getPublic()));

        KeyInfo privKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPrivate());
        assertEquals(KeyType.ASYMMETRIC, privKeyInfo.getKeyType());
        assertEquals(KeyPairType.EC.jce(), privKeyInfo.getAlgorithm());
//        assertEquals(keySize, privKeyInfo.getSize());
        assertEquals(curveName, privKeyInfo.getDetailedAlgorithm());

        KeyInfo pubKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPublic());
        assertEquals(KeyType.ASYMMETRIC, pubKeyInfo.getKeyType());
        assertEquals(KeyPairType.EC.jce(), pubKeyInfo.getAlgorithm());
//        assertEquals(keySize, pubKeyInfo.getSize());
//        assertEquals(curveName, pubKeyInfo.getDetailedAlgorithm());

        assertEquals(KeyPairType.EC, KeyPairUtil.getKeyPairType(keyPair.getPrivate()));
        assertEquals(KeyPairType.EC, KeyPairUtil.getKeyPairType(keyPair.getPublic()));
    }

    @ParameterizedTest
    // @formatter:off
    @ValueSource(strings = {
            // Edwards curves
            "ED25519", "ED448"
    })
    // @formatter:on
    void generateEdKeys(KeyPairType keyPairType) throws Exception {
        KeyPair keyPair = KeyPairUtil.generateECKeyPair(keyPairType.jce(), KSE.BC);
        assertTrue(KeyPairUtil.validKeyPair(keyPair.getPrivate(), keyPair.getPublic()));

        KeyInfo privKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPrivate());
        assertEquals(KeyType.ASYMMETRIC, privKeyInfo.getKeyType());
        assertEquals(keyPairType.jce(), privKeyInfo.getAlgorithm());
        assertEquals(keyPairType.maxSize(), privKeyInfo.getSize());
        assertEquals("-", privKeyInfo.getDetailedAlgorithm());

        KeyInfo pubKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPublic());
        assertEquals(KeyType.ASYMMETRIC, pubKeyInfo.getKeyType());
        assertEquals(keyPairType.jce(), pubKeyInfo.getAlgorithm());
        assertEquals(keyPairType.maxSize(), pubKeyInfo.getSize());
        assertEquals("-", pubKeyInfo.getDetailedAlgorithm());
    }

    @ParameterizedTest
    // @formatter:off
    @ValueSource(strings = {
            // GOST 3410 curves
            "GostR3410-2001-CryptoPro-A", "GostR3410-2001-CryptoPro-B", "GostR3410-2001-CryptoPro-C",
            "GostR3410-2001-CryptoPro-XchA", "GostR3410-2001-CryptoPro-XchB"
    })
    // @formatter:on
    void generateGost3410Keys(String curveName) throws Exception {
        KeyPair keyPair = KeyPairUtil.generateECKeyPair(curveName, KSE.BC);
        assertTrue(KeyPairUtil.validKeyPair(keyPair.getPrivate(), keyPair.getPublic()));

        KeyInfo privKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPrivate());
        assertEquals(KeyType.ASYMMETRIC, privKeyInfo.getKeyType());
        assertEquals(KeyPairType.ECGOST3410.jce(), privKeyInfo.getAlgorithm());
        assertEquals(KeyPairType.ECGOST3410.maxSize(), privKeyInfo.getSize());
        assertEquals(curveName, privKeyInfo.getDetailedAlgorithm());

        KeyInfo pubKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPublic());
        assertEquals(KeyType.ASYMMETRIC, pubKeyInfo.getKeyType());
        assertEquals(KeyPairType.ECGOST3410.jce(), pubKeyInfo.getAlgorithm());
        assertEquals(KeyPairType.ECGOST3410.maxSize(), pubKeyInfo.getSize());
        assertEquals(curveName, pubKeyInfo.getDetailedAlgorithm());

        assertEquals(KeyPairType.ECGOST3410, KeyPairUtil.getKeyPairType(keyPair.getPrivate()));
        assertEquals(KeyPairType.ECGOST3410, KeyPairUtil.getKeyPairType(keyPair.getPublic()));
    }

    @ParameterizedTest
    // @formatter:off
    @ValueSource(strings = {
            // GOST 3410-2012 curves
            "Tc26-Gost-3410-12-256-paramSetA", "Tc26-Gost-3410-12-256-paramSetB", "Tc26-Gost-3410-12-256-paramSetC",
            "Tc26-Gost-3410-12-256-paramSetD", "Tc26-Gost-3410-12-512-paramSetA", "Tc26-Gost-3410-12-512-paramSetB",
            "Tc26-Gost-3410-12-512-paramSetC",
    })
    // @formatter:on
    void generate3410_2012Keys(String curveName) throws Exception {
        KeyPair keyPair = KeyPairUtil.generateECKeyPair(curveName, KSE.BC);
        assertTrue(KeyPairUtil.validKeyPair(keyPair.getPrivate(), keyPair.getPublic()));

        KeyInfo privKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPrivate());
        assertEquals(KeyType.ASYMMETRIC, privKeyInfo.getKeyType());
        assertEquals(KeyPairType.ECGOST3410_2012.jce(), privKeyInfo.getAlgorithm());
//        assertEquals(keySize, privKeyInfo.getSize());
        assertEquals(curveName, privKeyInfo.getDetailedAlgorithm());

        KeyInfo pubKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPublic());
        assertEquals(KeyType.ASYMMETRIC, pubKeyInfo.getKeyType());
        assertEquals(KeyPairType.ECGOST3410_2012.jce(), pubKeyInfo.getAlgorithm());
//        assertEquals(keySize, pubKeyInfo.getSize());
        assertEquals(curveName, pubKeyInfo.getDetailedAlgorithm());

        assertEquals(KeyPairType.ECGOST3410_2012, KeyPairUtil.getKeyPairType(keyPair.getPrivate()));
        assertEquals(KeyPairType.ECGOST3410_2012, KeyPairUtil.getKeyPairType(keyPair.getPublic()));
    }

    @Test
    void testValidKeyPairWithDifferentAlgorithmNames()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CryptoException,
                   InvalidKeySpecException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", KSE.BC);
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1"), SecureRandom.getInstance("SHA1PRNG"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // private key has algorithm "ECDSA" (because it was generated by BC)
        PrivateKey privateKey = keyPair.getPrivate();

        // now convert public key to standard JCE object (so it has algorithm name "EC" instead of "ECDSA")
        PublicKey publicKey = KeyFactory.getInstance("EC")
                                        .generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));

        assertTrue(KeyPairUtil.validKeyPair(privateKey, publicKey));
    }

    @ParameterizedTest
    @MethodSource("mldsaVariants")
    void shouldGenerateAndValidateMLDSA(KeyPairType keyPairType) throws Exception {
        KeyPair keyPair = KeyPairUtil.generateKeyPair(keyPairType, KSE.BC);
        assertTrue(KeyPairUtil.validKeyPair(keyPair.getPrivate(), keyPair.getPublic()));

        KeyInfo privKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPrivate());
        assertEquals(KeyType.ASYMMETRIC, privKeyInfo.getKeyType());
        assertEquals(keyPairType.jce(), privKeyInfo.getAlgorithm());
        assertEquals(keyPairType.maxSize(), privKeyInfo.getSize());
        assertEquals("-", privKeyInfo.getDetailedAlgorithm());

        KeyInfo pubKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPublic());
        assertEquals(KeyType.ASYMMETRIC, pubKeyInfo.getKeyType());
        assertEquals(keyPairType.jce(), pubKeyInfo.getAlgorithm());
        assertEquals(keyPairType.maxSize(), pubKeyInfo.getSize());
        assertEquals("-", pubKeyInfo.getDetailedAlgorithm());

        assertEquals(keyPairType, KeyPairUtil.getKeyPairType(keyPair.getPrivate()));
        assertEquals(keyPairType, KeyPairUtil.getKeyPairType(keyPair.getPublic()));
    }

    @ParameterizedTest
    @ValueSource(strings = { "SunJCE" }) // "SUN" provider works when using Java 25
    void shouldThrowOnWrongProviderForMLDSA(String providerName) {
        Provider provider = Security.getProvider(providerName);
        assumeTrue(provider != null, "Provider " + providerName + " not available");

        assertThrows(
                CryptoException.class,
                () -> KeyPairUtil.generateKeyPair(KeyPairType.MLDSA44, provider)
        );
    }

    private static Set<KeyPairType> mldsaVariants() {
        return KeyPairType.MLDSA_TYPES_SET;
    }

    @ParameterizedTest
    @MethodSource("slhDsaVariants")
    void shouldGenerateAndValidateSlhDsa(KeyPairType keyPairType) throws Exception {
        KeyPair keyPair = KeyPairUtil.generateKeyPair(keyPairType, KSE.BC);
        assertTrue(KeyPairUtil.validKeyPair(keyPair.getPrivate(), keyPair.getPublic()));

        KeyInfo privKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPrivate());
        assertEquals(KeyType.ASYMMETRIC, privKeyInfo.getKeyType());
        assertEquals(keyPairType.jce(), privKeyInfo.getAlgorithm());
        assertEquals(keyPairType.maxSize(), privKeyInfo.getSize());
        assertEquals("-", privKeyInfo.getDetailedAlgorithm());

        KeyInfo pubKeyInfo = KeyPairUtil.getKeyInfo(keyPair.getPublic());
        assertEquals(KeyType.ASYMMETRIC, pubKeyInfo.getKeyType());
        assertEquals(keyPairType.jce(), pubKeyInfo.getAlgorithm());
        assertEquals(keyPairType.maxSize(), pubKeyInfo.getSize());
        assertEquals("-", pubKeyInfo.getDetailedAlgorithm());

        assertEquals(keyPairType, KeyPairUtil.getKeyPairType(keyPair.getPrivate()));
        assertEquals(keyPairType, KeyPairUtil.getKeyPairType(keyPair.getPublic()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SUN", "SunJCE"})
    void shouldThrowOnWrongProviderForSlhDsa(String providerName) {
        Provider provider = Security.getProvider(providerName);
        assumeTrue(provider != null, "Provider " + providerName + " not available");

        assertThrows(CryptoException.class, () -> KeyPairUtil.generateKeyPair(KeyPairType.SLHDSA_SHA2_128F, provider));
    }

    private static Set<KeyPairType> slhDsaVariants() {
        return KeyPairType.SLHDSA_TYPES_SET;
    }

    @Test
    void getKeyInfoNullKey() throws Exception {
        KeyInfo pubKeyInfo = KeyPairUtil.getKeyInfo((PublicKey) null);
        assertEquals(KeyType.ASYMMETRIC, pubKeyInfo.getKeyType());
        assertEquals("", pubKeyInfo.getAlgorithm());
        assertNull(pubKeyInfo.getSize());

        KeyInfo privKeyInfo = KeyPairUtil.getKeyInfo((PrivateKey) null);
        assertEquals(KeyType.ASYMMETRIC, privKeyInfo.getKeyType());
        assertEquals("", privKeyInfo.getAlgorithm());
        assertNull(privKeyInfo.getSize());
    }

}
