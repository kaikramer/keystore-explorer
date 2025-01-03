/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
package org.kse.crypto.publickey;

import com.nimbusds.jose.JOSEException;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.kse.crypto.jwk.JwkExporterException;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Execution(ExecutionMode.CONCURRENT)
public class JwkPublicKeyExporterTest {
    @BeforeAll
    public static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }
    @Nested
    class ForRSA {
        private final RSAPublicKeySpec rsaPublicKeySpec;
        private RSAPublicKey rsaPublicKey;

        ForRSA() throws InvalidKeySpecException, NoSuchAlgorithmException {
            BigInteger modulus = new BigInteger(
                    "00c1b4c7b1d4d3a72950c1df4c67fe2192679855829161e5825c9dc29c88a00a54c42260d55e3569db33efb63b9a568d913735a7dbdcae6937ab967bd93d35ecf7326c1d132896bbfbc7b73c0fb09d7ef92cc0484fa616cd92a0458028ad69d7e0b662e7c1115f08c5e74a43f50832c9e04125fd3311aa6d183b87b9b3d593bb",
                    16);
            BigInteger exponent = new BigInteger("10001", 16);
            rsaPublicKeySpec =  new RSAPublicKeySpec(modulus, exponent);
            rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);
        }
        @Test
        public void shouldExportRSAPublicKeyWithAlias() throws JOSEException, JSONException {
            JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(rsaPublicKey, "testAlias");
            String exportedKey = new String(exporter.get());

            String expectedJson = "{" +
                                  "\"kty\":\"RSA\"," +
                                  "\"n\":\"wbTHsdTTpylQwd9MZ_4hkmeYVYKRYeWCXJ3CnIigClTEImDVXjVp2zPvtjuaVo2RNzWn29yuaTerlnvZPTXs9zJsHRMolrv7x7c8D7CdfvkswEhPphbNkqBFgCitadfgtmLnwRFfCMXnSkP1CDLJ4EEl_TMRqm0YO4e5s9WTuw\"," +
                                  "\"e\":\"AQAB\"," +
                                  "\"kid\":\"testAlias\"" +
                                  "}";
            JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
        }

        @Test
        public void shouldExportRSAPublicKeyWithoutAlias() throws JSONException {
            JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(rsaPublicKey, null);
            String exportedKey = new String(exporter.get());

            String expectedJson = "{" +
                                  "\"kty\":\"RSA\"," +
                                  "\"n\":\"wbTHsdTTpylQwd9MZ_4hkmeYVYKRYeWCXJ3CnIigClTEImDVXjVp2zPvtjuaVo2RNzWn29yuaTerlnvZPTXs9zJsHRMolrv7x7c8D7CdfvkswEhPphbNkqBFgCitadfgtmLnwRFfCMXnSkP1CDLJ4EEl_TMRqm0YO4e5s9WTuw\"," +
                                  "\"e\":\"AQAB\"," +
                                  "\"kid\":\"O5S4xk_n66c64bA1zSz4KVIGFRaxvgbtUKGLoNMSYLw\"" +
                                  "}";
            JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
        }
    }
    @Nested
    class ForEC {
        private ECPublicKey ecPublicKey;
        public ForEC() throws NoSuchAlgorithmException, InvalidKeySpecException {
            EllipticCurve ellipticCurve = new EllipticCurve(
                    new ECFieldFp(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
                    new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
                    new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16));
            ECPoint ecPoint = new ECPoint(
                    new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
                    new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16));
            ECParameterSpec ecParameterSpec = new ECNamedCurveSpec("secp256r1", ellipticCurve, ecPoint, new BigInteger(
                    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16));
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            this.ecPublicKey = (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
        }

        @Test
        public void shouldExportECPublicKeyWithAlias() throws JSONException {
            JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(ecPublicKey, "testAlias");
            String exportedKey = new String(exporter.get());
            String expectedJson =
                    "{" +
                    "\"kty\":\"EC\"," +
                    "\"crv\":\"P-256\"," +
                    "\"x\":\"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY\"," +
                    "\"y\":\"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU\"," +
                    "\"kid\":\"testAlias\"" +
                    "}";
            JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
        }

        @Test
        public void shouldExportECPublicKeyWithoutAlias() throws JSONException {
            JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(ecPublicKey, null);
            String exportedKey = new String(exporter.get());

            String expectedJson =
                    "{" +
                    "\"kty\":\"EC\",\"crv\":\"P-256\"," +
                    "\"x\":\"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY\"," +
                    "\"y\":\"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU\"," +
                    "\"kid\":\"xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M\"" +
                    "}";
            JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
        }
        @Test
        void throwsJwkExporterExceptionWhenExportingUnsupportedCurve()
                throws NoSuchAlgorithmException, InvalidKeySpecException {
            EllipticCurve ellipticCurve = new EllipticCurve(
                    new ECFieldFp(new BigInteger("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", 16)),
                    new BigInteger("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC", 16),
                    new BigInteger("E87579C11079F43DD824993C2CEE5ED3", 16));
            ECPoint ecPoint = new ECPoint(
                    new BigInteger("161FF7528B899B2D0C28607CA52C5B86", 16),
                    new BigInteger("CF5AC8395BAFEB13C02DA292DDED7A83", 16));
            ECParameterSpec ecParameterSpec = new ECNamedCurveSpec(
                    "secp128r1",
                    ellipticCurve,
                    ecPoint,
                    new BigInteger("FFFFFFFE0000000075A30D1B9038A115", 16)
            );
            ECPublicKeySpec unsupportedECPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            ECPublicKey unsupportedECPublicKey = (ECPublicKey) keyFactory.generatePublic(unsupportedECPublicKeySpec);

            JwkPublicKeyExporter jwkPublicKeyExporter = JwkPublicKeyExporter.from(unsupportedECPublicKey, null);
            assertThrows(JwkExporterException.class, jwkPublicKeyExporter::get);
        }
    }

    @Nested
    class ForEdDSA{
        @Test
        public void shouldExportEd25519PublicKeyWithoutAlias() throws JSONException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
            byte[] spkiEncoded = Hex.decode("302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(spkiEncoded);
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", "BC");

            BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyFactory.generatePublic(keySpec);
            JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(publicKey, null);
            String exportedKey = new String(exporter.get());

            String expectedJson =
                    "{" +
                    "\"kty\":\"OKP\","
                    + "\"crv\":\"Ed25519\","
                    + "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\","
                    + "\"kid\":\"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k\"" +
                    "}";
            JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
        }

        @Test
        public void shouldExportEd448PublicKeyWithAlias() throws JSONException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
            byte[] spkiEncoded = Hex.decode("3043300506032b6571033a005fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(spkiEncoded);
            KeyFactory keyFactory = KeyFactory.getInstance("Ed448", "BC");

            BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyFactory.generatePublic(keySpec);
            JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(publicKey, "testAlias");
            String exportedKey = new String(exporter.get());

            String expectedJson =
                    "{" +
                    "\"kty\":\"OKP\"," +
                    "\"crv\":\"Ed448\"," +
                    "\"x\":\"X9dEm1m0Yf0s54fsYWrUah2hNCSFpw4fig6nXYDpZ3jt8SR2m0bHBhvWeD3x5Q9s0foavq_oJWGA\"," +
                    "\"kid\":\"testAlias\"" +
                    "}";
            JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
        }
    }

    @Test
    void handlesAttemptToExportUnsupportedEdDSAKeyWithGrace()  {
        assertThrows(JwkExporterException.class, () -> {
            BCEdDSAPublicKey publicKeyMock = mock(BCEdDSAPublicKey.class);
            when(publicKeyMock.getAlgorithm()).thenReturn("UnsupportedCurve");
            JwkPublicKeyExporter jwkPublicKeyExporter = JwkPublicKeyExporter.from(publicKeyMock, null);
            jwkPublicKeyExporter.get();
        });
    }

    @Test
    void handlesUnsupportedPublicKeyTypeWithGrace() throws JOSEException {
        PublicKey unsupportedKey = new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "DSA";
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };
        assertThrows(JwkExporterException.class, ()-> JwkPublicKeyExporter.from(unsupportedKey, "testAlias"));
    }
}
