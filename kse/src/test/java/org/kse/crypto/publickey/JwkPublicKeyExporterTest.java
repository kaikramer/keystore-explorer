package org.kse.crypto.publickey;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.json.JSONException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import com.nimbusds.jose.JOSEException;

@Execution(ExecutionMode.CONCURRENT)
public class JwkPublicKeyExporterTest {
    private static ECPublicKey ecPublicKey;
    private static RSAPublicKey rsaPublicKey;

    private static RSAPublicKeySpec getRsaPublicKeySpec() {
        BigInteger modulus = new BigInteger(
                "00c1b4c7b1d4d3a72950c1df4c67fe2192679855829161e5825c9dc29c88a00a54c42260d55e3569db33efb63b9a568d913735a7dbdcae6937ab967bd93d35ecf7326c1d132896bbfbc7b73c0fb09d7ef92cc0484fa616cd92a0458028ad69d7e0b662e7c1115f08c5e74a43f50832c9e04125fd3311aa6d183b87b9b3d593bb",
                16);
        BigInteger exponent = new BigInteger("10001", 16);
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        return rsaPublicKeySpec;
    }

    private static ECPublicKeySpec getEcPublicKeySpec() {
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
        return ecPublicKeySpec;
    }

    @BeforeAll
    public static void setUp() throws Exception {
        ECPublicKeySpec ecPublicKeySpec = getEcPublicKeySpec();
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ecPublicKey = (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);

        RSAPublicKeySpec rsaPublicKeySpec = getRsaPublicKeySpec();
        rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);
    }

    @Test
    public void shouldExportECPublicKeyWithAlias() throws JOSEException, JSONException {
        JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(ecPublicKey, "testAlias");
        String exportedKey = new String(exporter.get());
        String expectedJson =
                "{\"kty\":\"EC\",\"crv\":\"P-256\"," + "\"x\":\"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY\"," +
                "\"y\":\"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU\"," + "\"kid\":\"testAlias\"}";
        JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
    }

    @Test
    public void shouldExportECPublicKeyWithoutAlias() throws JOSEException, JSONException {
        JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(ecPublicKey, null);
        String exportedKey = new String(exporter.get());

        String expectedJson =
                "{\"kty\":\"EC\",\"crv\":\"P-256\"," + "\"x\":\"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY\"," +
                "\"y\":\"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU\"," +
                "\"kid\":\"xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M\"}";
        JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
    }

    @Test
    void shouldExportRSAPublicKey(){
        JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(rsaPublicKey, "testAlias");
        Assertions.assertTrue(exporter.canExport());
    }

    @Test
    public void shouldExportRSAPublicKeyWithAlias() throws JOSEException, JSONException {
        JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(rsaPublicKey, "testAlias");
        String exportedKey = new String(exporter.get());

        String expectedJson = "{\"kty\":\"RSA\"," +
                              "\"n\":\"wbTHsdTTpylQwd9MZ_4hkmeYVYKRYeWCXJ3CnIigClTEImDVXjVp2zPvtjuaVo2RNzWn29yuaTerlnvZPTXs9zJsHRMolrv7x7c8D7CdfvkswEhPphbNkqBFgCitadfgtmLnwRFfCMXnSkP1CDLJ4EEl_TMRqm0YO4e5s9WTuw\"," +
                              "\"e\":\"AQAB\",\"kid\":\"testAlias\"}";
        JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
    }

    @Test
    public void shouldExportRSAPublicKeyWithoutAlias() throws JOSEException, JSONException {
        JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(rsaPublicKey, null);
        String exportedKey = new String(exporter.get());

        String expectedJson = "{\"kty\":\"RSA\"," +
                              "\"n\":\"wbTHsdTTpylQwd9MZ_4hkmeYVYKRYeWCXJ3CnIigClTEImDVXjVp2zPvtjuaVo2RNzWn29yuaTerlnvZPTXs9zJsHRMolrv7x7c8D7CdfvkswEhPphbNkqBFgCitadfgtmLnwRFfCMXnSkP1CDLJ4EEl_TMRqm0YO4e5s9WTuw\"," +
                              "\"e\":\"AQAB\",\"kid\":\"O5S4xk_n66c64bA1zSz4KVIGFRaxvgbtUKGLoNMSYLw\"}";
        JSONAssert.assertEquals(expectedJson, exportedKey, JSONCompareMode.STRICT);
    }

    @ParameterizedTest
    @ValueSource(
            strings = { "prime256v1", "secp256r1", "NIST P-256", "secp256k1", "secp384r1", "NIST P-384", "secp521r1",
                        "NIST P-521", "Ed25519", "Ed2448" })
    void supportsECCurve(String curveName) {
        ECPublicKey ecPublicKeyMock = mock(ECPublicKey.class);
        ECNamedCurveSpec specMock = mock(ECNamedCurveSpec.class);
        when(ecPublicKeyMock.getParams()).thenReturn(specMock);
        when(specMock.getName()).thenReturn(curveName);
        JwkPublicKeyExporter jwkPublicKeyExporter = JwkPublicKeyExporter.from(ecPublicKeyMock, null);
        assertTrue(jwkPublicKeyExporter.canExport());
    }
    @Test
    void supportsOnlyNamedECCurveSpec() {
        ECPublicKey ecPublicKeyMock = mock(ECPublicKey.class);
        ECParameterSpec specMock = mock(ECParameterSpec.class);
        when(ecPublicKeyMock.getParams()).thenReturn(specMock);
        JwkPublicKeyExporter jwkPublicKeyExporter = JwkPublicKeyExporter.from(ecPublicKeyMock, null);
        assertFalse(jwkPublicKeyExporter.canExport());
    }
    @Test
    void shouldHandleAttemptToExportUnsupportedCurveKeyWithGrace()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
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
        Assertions.assertFalse(jwkPublicKeyExporter.canExport());
        Assertions.assertArrayEquals(jwkPublicKeyExporter.get(), new byte[0]);
    }
    @Test
    void shouldHandleUnsupportedPublicKeyTypeWithGrace() throws JOSEException {
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

        JwkPublicKeyExporter exporter = JwkPublicKeyExporter.from(unsupportedKey, "testAlias");
        Assertions.assertFalse(exporter.canExport());
        Assertions.assertEquals(exporter.get().length, 0);
    }
}
