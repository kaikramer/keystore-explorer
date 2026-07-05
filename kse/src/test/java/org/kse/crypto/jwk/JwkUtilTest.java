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
package org.kse.crypto.jwk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.keypair.KeyPairUtil;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;

class JwkUtilTest {
    @Nested
    class EdDSAExporter {
        private byte[] encodePrivateKey(byte[] privateKeyScalar, String curve) throws IOException {
            ASN1ObjectIdentifier oid;
                switch (curve) {
                case "Ed448":
                    oid = EdECObjectIdentifiers.id_Ed448;
                    break;
                case "Ed25519":
                    oid = EdECObjectIdentifiers.id_Ed25519;
                    break;
                default:
                    throw new IllegalArgumentException(curve);
                }
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1Integer(0));

            ASN1Sequence algIdSeq = new DERSequence(new ASN1Encodable[] { oid });
            vector.add(algIdSeq);

            vector.add(new DEROctetString(new DEROctetString(privateKeyScalar)));  // Wrap the first OCTET STRING
            ASN1Sequence privateKeyInfo = new DERSequence(vector);

            return privateKeyInfo.getEncoded(ASN1Encoding.DER);
        }

        KeyPair createEdDSAPrivateKey(String name, byte[] d) throws Exception {
            Security.addProvider(new BouncyCastleProvider());
            byte[] pkcs8EncodedKey = encodePrivateKey(d, name);
            KeyFactory keyFactory = KeyFactory.getInstance(name, "BC");

            EdDSAPrivateKey privateKey = (EdDSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedKey));
            return new KeyPair(privateKey.getPublicKey(), privateKey);
        }
        @Nested
        class ForEd25519{
            byte[] d = Hex.decode("DCAAACEADDAC99D31020B81795E1F64CA36D81701034EE598C161F2655368F76");
            KeyPair keyPair = createEdDSAPrivateKey("Ed25519", d);
            byte[] certBytes = Hex.decode("3081dd308190a00302010202141122334455667788990011223344556677889900"
                                        + "300506032b6570300f310d300b06035504030c0443657274301e170d3236303632"
                                        + "353034313634385a170d3336303632323034313634385a300f310d300b06035504"
                                        + "030c0443657274302a300506032b65700321001420b3e4e4c182d7983e72e71509"
                                        + "3976a4a5d5f9dc939b643224f5597ff2e37c300506032b6570034100f2b0f51ce9"
                                        + "573d23726e1ce5fbddec5b4ef8421a57864b64ce36abde45085c0feaf49adb795d"
                                        + "3adae1213ab19a01a02a06920c9a6e4e39be8f9c7602e471ec02");
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certBytes));

            ForEd25519() throws Exception {}

            private final String expectedJwkPub =
                    "{\n" +
                    "  \"kty\": \"OKP\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"Ed25519\",\n" +
                    "  \"x\": \"FCCz5OTBgteYPnLnFQk5dqSl1fnck5tkMiT1WX_y43w\"\n" +
                    "}";
            private final String expectedJwk =
                    "{\n" +
                    "  \"kty\": \"OKP\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"Ed25519\",\n" +
                    "  \"x\": \"FCCz5OTBgteYPnLnFQk5dqSl1fnck5tkMiT1WX_y43w\",\n" +
                    "  \"d\": \"3Kqs6t2smdMQILgXleH2TKNtgXAQNO5ZjBYfJlU2j3Y\"\n" +
                    "}";
            private final String expectedJwkCert =
                    "{\n" +
                    "  \"kty\": \"OKP\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"Ed25519\",\n" +
                    "  \"x\": \"FCCz5OTBgteYPnLnFQk5dqSl1fnck5tkMiT1WX_y43w\",\n" +
                    "  \"d\": \"3Kqs6t2smdMQILgXleH2TKNtgXAQNO5ZjBYfJlU2j3Y\",\n" +
                    "  \"exp\": 2097721008,\n" +
                    "  \"nbf\": 1782361008,\n" +
                    "  \"x5c\": [\"MIHdMIGQoAMCAQICFBEiM0RVZneImQARIjNEVWZ3iJkAMAUGAytlcDAPMQ0wCwYDVQQDDARDZXJ0MB4XDTI2MDYyNTA0MTY0OFoXDTM2MDYyMjA0MTY0OFowDzENMAsGA1UEAwwEQ2VydDAqMAUGAytlcAMhABQgs+TkwYLXmD5y5xUJOXakpdX53JObZDIk9Vl/8uN8MAUGAytlcANBAPKw9RzpVz0jcm4c5fvd7FtO+EIaV4ZLZM42q95FCFwP6vSa23ldOtrhITqxmgGgKgaSDJpuTjm+j5x2AuRx7AI=\"],\n" +
                    "  \"x5t\": \"-U4TpoUTlmWxUaxixQ8ehUz6c6A\",\n" +
                    "  \"x5t#S256\": \"EyMzMKoskyRgNofI1NwmekJryVoZEhR3cLKEg3SoAH4\"\n" +
                    "}";
            @Test
            void shouldExportWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias");
                JSONAssert.assertEquals(expectedJwk, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }
            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), null);
                JSONAssert.assertEquals(
                        expectedJwk.replace("alias", "hMKYp7HryDQcWc9sdicmx4x0l7BXvkeZCbMm6fYH_UM"),
                        actualJwk,
                        JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }
            @Test
            void shouldExportWithProvidedCert() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias", new X509Certificate[] {cert});
                JSONAssert.assertEquals(expectedJwkCert, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertArrayEquals(cert.getEncoded(), jwk.getParsedX509CertChain().get(0).getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(),
                        jwk.getParsedX509CertChain().get(0).getPublicKey().getEncoded());
            }
            @Test
            void shouldExportPublicWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPublic(), "alias");
                JSONAssert.assertEquals(expectedJwkPub, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertNull(actualPrivateKey);
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }
        }
        @Nested
        class ForEd448{
            byte[] d = Hex.decode("0DAAE3F2A4AC597FD67BEE8F46F50AE24CD67D53F846BE5DEB6ACE0CB67FD9EA95604FBDEF9F566A4245C9A5BAB81FD8DC0AF3179CE94C4084");
            KeyPair keyPair = createEdDSAPrivateKey("Ed448", d);
            byte[] certBytes = Hex.decode("308201283081a9a0030201020214112233445566778899001122334455667788"
                                        + "9900300506032b6571300f310d300b06035504030c0443657274301e170d3236"
                                        + "303632353035313732305a170d3336303632323035313732305a300f310d300b"
                                        + "06035504030c04436572743043300506032b6571033a002786a692d4053643d5"
                                        + "fde8bcf94886be2c6863cb1a2bbfffe0b2fa68b9cb58bccb4e914865d240d7b4"
                                        + "fd86a15fcdec60a701380bb2de03c800300506032b65710373007ebd46a19fb9"
                                        + "64807d43579b3711b629eceb49c7707bf498c76cec2f5661320d694b0f1fee1d"
                                        + "7de75ffdf3056c108462e3960565eae6d42c00f4932b93616804228a8c12ecde"
                                        + "9c54cda85639f55e15e4aa8968e8ab9d476939da55e75598afcacc333ad3e844"
                                        + "61a19d131c9ffa17a5912d00");
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certBytes));

            ForEd448() throws Exception {}

            private final String expectedJwkPub =
                    "{\n" +
                    "  \"kty\": \"OKP\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"Ed448\",\n" +
                    "  \"x\": \"J4amktQFNkPV_ei8-UiGvixoY8saK7__4LL6aLnLWLzLTpFIZdJA17T9hqFfzexgpwE4C7LeA8gA\"\n" +
                    "}";
            private final String expectedJwk =
                    "{\n" +
                    "  \"kty\": \"OKP\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"Ed448\",\n" +
                    "  \"x\": \"J4amktQFNkPV_ei8-UiGvixoY8saK7__4LL6aLnLWLzLTpFIZdJA17T9hqFfzexgpwE4C7LeA8gA\",\n" +
                    "  \"d\": \"Darj8qSsWX_We-6PRvUK4kzWfVP4Rr5d62rODLZ_2eqVYE-9759WakJFyaW6uB_Y3ArzF5zpTECE\"\n" +
                    "}";
            private final String expectedJwkCert =
                    "{\n" +
                    "  \"kty\": \"OKP\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"Ed448\",\n" +
                    "  \"x\": \"J4amktQFNkPV_ei8-UiGvixoY8saK7__4LL6aLnLWLzLTpFIZdJA17T9hqFfzexgpwE4C7LeA8gA\",\n" +
                    "  \"d\": \"Darj8qSsWX_We-6PRvUK4kzWfVP4Rr5d62rODLZ_2eqVYE-9759WakJFyaW6uB_Y3ArzF5zpTECE\",\n" +
                    "  \"exp\": 2097724640,\n" +
                    "  \"nbf\": 1782364640,\n" +
                    "  \"x5c\": [\"MIIBKDCBqaADAgECAhQRIjNEVWZ3iJkAESIzRFVmd4iZADAFBgMrZXEwDzENMAsGA1UEAwwEQ2VydDAeFw0yNjA2MjUwNTE3MjBaFw0zNjA2MjIwNTE3MjBaMA8xDTALBgNVBAMMBENlcnQwQzAFBgMrZXEDOgAnhqaS1AU2Q9X96Lz5SIa+LGhjyxorv//gsvpouctYvMtOkUhl0kDXtP2GoV/N7GCnATgLst4DyAAwBQYDK2VxA3MAfr1GoZ+5ZIB9Q1ebNxG2KezrScdwe/SYx2zsL1ZhMg1pSw8f7h1951/98wVsEIRi45YFZerm1CwA9JMrk2FoBCKKjBLs3pxUzahWOfVeFeSqiWjoq51HaTnaVedVmK/KzDM60+hEYaGdExyf+helkS0A\"],\n" +
                    "  \"x5t\": \"PUlcuPfjxSgXV7wfpSP00cYA3ug\",\n" +
                    "  \"x5t#S256\": \"w88hAqFloCYolIx3uJg0bZdjiUy1S-eybUUX141Ros4\"\n" +
                    "}";
            @Test
            void shouldExportWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias");
                JSONAssert.assertEquals(expectedJwk, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }
            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), null);
                JSONAssert.assertEquals(
                        expectedJwk.replace("alias", "nH74MmF8qGFGAXy5TjR7fRg2oNadcEM5q0c3X3AZSnU"),
                        actualJwk,
                        JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }
            @Test
            void shouldExportWithProvidedCert() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias", new X509Certificate[] {cert});
                JSONAssert.assertEquals(expectedJwkCert, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertArrayEquals(cert.getEncoded(), jwk.getParsedX509CertChain().get(0).getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(),
                        jwk.getParsedX509CertChain().get(0).getPublicKey().getEncoded());
            }
            @Test
            void shouldExportPublicWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPublic(), "alias");
                JSONAssert.assertEquals(expectedJwkPub, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertNull(actualPrivateKey);
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }
        }

        @Test
        void handlesAttemptToExportUnsupportedEdDSAKeyWithGrace()  {
            assertThrows(IllegalArgumentException.class, () -> {
                EdDSAPublicKey publicKeyMock = mock(EdDSAPublicKey.class);
                when(publicKeyMock.getAlgorithm()).thenReturn("UnsupportedCurve");
                JwkUtil.get(publicKeyMock, null);
            });
        }
    }
    @Nested
    class ECExporter {
         KeyPair createECKeyPair(String name, BigInteger x, BigInteger y, BigInteger d) throws Exception {
             Security.addProvider(KSE.BC);
             Curve crv = Curve.forStdName(name);

             // Don't use BC provider. It generates explicitly specified curves rather than named curves.
             KeyFactory keyFactory = KeyFactory.getInstance("EC");
             ECPoint ecPoint = new ECPoint(x, y);
             PrivateKey privateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(d, crv.toECParameterSpec()));
             PublicKey publicKey = keyFactory.generatePublic(new ECPublicKeySpec(ecPoint, crv.toECParameterSpec()));

             return new KeyPair(publicKey, privateKey);
        }
        @Nested
        class ForP256 {
            private final BigInteger x = new BigInteger("31280353521748007751073210519124413952960573603543172459705786372726920157623");
            private final BigInteger y = new BigInteger("50617793630519936901357235932215616294808241623855566885030507888158404684632");
            private final BigInteger d = new BigInteger("32781779821477417998876315633523231413990355816295546824195829039048772249565");
            private final KeyPair keyPair = createECKeyPair("secp256r1", x, y, d);
            private final byte[] certBytes = Hex.decode("3082011e3081c4a0030201020214112233445566778899001122334455667788"
                                                      + "9900300a06082a8648ce3d040302300f310d300b06035504030c044365727430"
                                                      + "1e170d3236303632353232333530335a170d3336303632323232333530335a30"
                                                      + "0f310d300b06035504030c04436572743059301306072a8648ce3d020106082a"
                                                      + "8648ce3d0301070342000445280d7cc9130619e1e468b37083e0e43d1e772049"
                                                      + "4a2fd462d1d159506599b76fe8a7eaaf7dab66a1de0817d5c7ad6c8477272d54"
                                                      + "e0dec2980efb779e2eab58300a06082a8648ce3d0403020349003046022100a1"
                                                      + "f6466d769cde93332a60dbfac44b5932d108fdf8f9b1f131ef7cbe4dc20c8a02"
                                                      + "2100c930b51e1ed5b015368dc1c7ba1ff47bcd272383ba874dd3f0b29c50cf10"
                                                      + "0463");
            private final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certBytes));

            ForP256() throws Exception {}

            private final String expectedJwkPub =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-256\",\n" +
                    "  \"x\": \"RSgNfMkTBhnh5GizcIPg5D0edyBJSi_UYtHRWVBlmbc\",\n" +
                    "  \"y\": \"b-in6q99q2ah3ggX1cetbIR3Jy1U4N7CmA77d54uq1g\"\n" +
                    "}";

            private final String expectedJwk =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-256\",\n" +
                    "  \"x\": \"RSgNfMkTBhnh5GizcIPg5D0edyBJSi_UYtHRWVBlmbc\",\n" +
                    "  \"y\": \"b-in6q99q2ah3ggX1cetbIR3Jy1U4N7CmA77d54uq1g\",\n" +
                    "  \"d\": \"SHnUcXFrnkaPGQLUeNWf_HTR-5vGNvM9eXiRRyUrZ90\"\n" +
                    "}";

            private final String expectedJwkCert =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-256\",\n" +
                    "  \"x\": \"RSgNfMkTBhnh5GizcIPg5D0edyBJSi_UYtHRWVBlmbc\",\n" +
                    "  \"y\": \"b-in6q99q2ah3ggX1cetbIR3Jy1U4N7CmA77d54uq1g\",\n" +
                    "  \"d\": \"SHnUcXFrnkaPGQLUeNWf_HTR-5vGNvM9eXiRRyUrZ90\",\n" +
                    "  \"exp\": 2097786903,\n" +
                    "  \"nbf\": 1782426903,\n" +
                    "  \"x5c\": [\"MIIBHjCBxKADAgECAhQRIjNEVWZ3iJkAESIzRFVmd4iZADAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARDZXJ0MB4XDTI2MDYyNTIyMzUwM1oXDTM2MDYyMjIyMzUwM1owDzENMAsGA1UEAwwEQ2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEUoDXzJEwYZ4eRos3CD4OQ9HncgSUov1GLR0VlQZZm3b+in6q99q2ah3ggX1cetbIR3Jy1U4N7CmA77d54uq1gwCgYIKoZIzj0EAwIDSQAwRgIhAKH2Rm12nN6TMypg2/rES1ky0Qj9+Pmx8THvfL5NwgyKAiEAyTC1Hh7VsBU2jcHHuh/0e80nI4O6h03T8LKcUM8QBGM=\"],\n" +
                    "  \"x5t\": \"EyQPb8FV2CKFZ1A99Bc6-VCLyHQ\",\n" +
                    "  \"x5t#S256\": \"nELxb4qnqThUp_QkY3KypozbnaLWr-elDr4ZF1Q9UDg\"\n" +
                    "}";

            @Test
            void shouldExportWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias");
                JSONAssert.assertEquals(expectedJwk, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }

            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), null);
                JSONAssert.assertEquals(
                    expectedJwk.replace("alias", "Z_nEaDZgcu_T0lTDG8e3t3jVXcSrz7l_zAUj8mDIr_s"),
                    actualJwk,
                    JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }

            @Test
            void shouldExportWithProvidedCert() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias", new X509Certificate[] {cert});
                JSONAssert.assertEquals(expectedJwkCert, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertArrayEquals(cert.getEncoded(), jwk.getParsedX509CertChain().get(0).getEncoded());
            }

            @Test
            void shouldExportPublicWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPublic(), "alias");
                JSONAssert.assertEquals(expectedJwkPub, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertNull(actualPrivateKey);
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
            }
        }
        @Nested
        class ForP384 {
            private final BigInteger x = new BigInteger("6573922393948971271618538764290418829390358805413025706361922917708788331582941015615751218406657948637307551233960");
            private final BigInteger y = new BigInteger("30793716447214955637070133689338913547405438829620835834347877457337662863851014549841414707353700521094322272411570");
            private final BigInteger d = new BigInteger("11412855896185886407544021730482897434230166598563390009018669816761555943280006817242861952641917289493292871922552");
            private final KeyPair keyPair = createECKeyPair("secp384r1", x, y, d);
            private final byte[] certBytes = Hex.decode("3082015a3081e1a0030201020214112233445566778899001122334455667788"
                                                      + "9900300a06082a8648ce3d040302300f310d300b06035504030c044365727430"
                                                      + "1e170d3236303632353232353230335a170d3336303632323232353230335a30"
                                                      + "0f310d300b06035504030c04436572743076301006072a8648ce3d020106052b"
                                                      + "81040022036200042ab62dc1255f244ce3fc42125b9870f33e4601fb702ff89b"
                                                      + "5670bcbcd01db5d452efbc2f0e5bc2f23cabf0a804aa37a8c81220cbb1f1eb65"
                                                      + "4a57b7740cd8203d00fc74f7917a3323dadaad6034892fa8f0c636ae81791325"
                                                      + "36ec41bd38951fb2300a06082a8648ce3d040302036800306502301030a8cb33"
                                                      + "6596183ba81c49d0ac9dd654a3053cb45723be03edc3ed4ae5769ccdd00c10cb"
                                                      + "4c85e53c90dd66bbf23c770231009ff32efa35faa70d083702b054fe5b71bbfc"
                                                      + "6f348ea440720e202ef5477544476c9fa0b8887dff96b0f9b7e6b6989b67");
            private final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certBytes));

            ForP384() throws Exception {}

            private final String expectedJwkPub =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-384\",\n" +
                    "  \"x\": \"KrYtwSVfJEzj_EISW5hw8z5GAftwL_ibVnC8vNAdtdRS77wvDlvC8jyr8KgEqjeo\",\n" +
                    "  \"y\": \"yBIgy7Hx62VKV7d0DNggPQD8dPeRejMj2tqtYDSJL6jwxjaugXkTJTbsQb04lR-y\"\n" +
                    "}";

            private final String expectedJwk =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-384\",\n" +
                    "  \"x\": \"KrYtwSVfJEzj_EISW5hw8z5GAftwL_ibVnC8vNAdtdRS77wvDlvC8jyr8KgEqjeo\",\n" +
                    "  \"y\": \"yBIgy7Hx62VKV7d0DNggPQD8dPeRejMj2tqtYDSJL6jwxjaugXkTJTbsQb04lR-y\",\n" +
                    "  \"d\": \"SiacNOIpuvY2xWgrMZwRZk6cllDjQkeKiijVbOZApPhbAJCUwZhZylwZ79g-UTN4\"\n" +
                    "}";

            private final String expectedJwkCert =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-384\",\n" +
                    "  \"x\": \"KrYtwSVfJEzj_EISW5hw8z5GAftwL_ibVnC8vNAdtdRS77wvDlvC8jyr8KgEqjeo\",\n" +
                    "  \"y\": \"yBIgy7Hx62VKV7d0DNggPQD8dPeRejMj2tqtYDSJL6jwxjaugXkTJTbsQb04lR-y\",\n" +
                    "  \"d\": \"SiacNOIpuvY2xWgrMZwRZk6cllDjQkeKiijVbOZApPhbAJCUwZhZylwZ79g-UTN4\",\n" +
                    "  \"exp\": 2097787923,\n" +
                    "  \"nbf\": 1782427923,\n" +
                    "  \"x5c\": [\"MIIBWjCB4aADAgECAhQRIjNEVWZ3iJkAESIzRFVmd4iZADAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARDZXJ0MB4XDTI2MDYyNTIyNTIwM1oXDTM2MDYyMjIyNTIwM1owDzENMAsGA1UEAwwEQ2VydDB2MBAGByqGSM49AgEGBSuBBAAiA2IABCq2LcElXyRM4/xCEluYcPM+RgH7cC/4m1ZwvLzQHbXUUu+8Lw5bwvI8q/CoBKo3qMgSIMux8etlSle3dAzYID0A/HT3kXozI9rarWA0iS+o8MY2roF5EyU27EG9OJUfsjAKBggqhkjOPQQDAgNoADBlAjAQMKjLM2WWGDuoHEnQrJ3WVKMFPLRXI74D7cPtSuV2nM3QDBDLTIXlPJDdZrvyPHcCMQCf8y76NfqnDQg3ArBU/ltxu/xvNI6kQHIOIC71R3VER2yfoLiIff+WsPm35raYm2c=\"],\n" +
                    "  \"x5t\": \"of5pcSUcnVg8daRqWMH6I4QnIzs\",\n" +
                    "  \"x5t#S256\": \"lhp-mNqXsIyri9z1UED3AscK7Lwf1F-yAe1o1bb5b_U\"\n" +
                    "}";

            @Test
            void shouldExportWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias");
                JSONAssert.assertEquals(expectedJwk, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }

            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), null);
                JSONAssert.assertEquals(
                    expectedJwk.replace("alias", "ikjIWnajHMom1vOGsa7KPn4gSZRITNrw-5tiwgxbqlc"),
                    actualJwk,
                    JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }

            @Test
            void shouldExportWithProvidedCert() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias", new X509Certificate[] {cert});
                JSONAssert.assertEquals(expectedJwkCert, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertArrayEquals(cert.getEncoded(), jwk.getParsedX509CertChain().get(0).getEncoded());
            }

            @Test
            void shouldExportPublicWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPublic(), "alias");
                JSONAssert.assertEquals(expectedJwkPub, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertNull(actualPrivateKey);
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
            }
        }
        @Nested
        class ForP521 {
            private final BigInteger x = new BigInteger("5616434552225233173085554449990053960371141125000984104097757555599558423583428015590040357489900890768442722598070143591422876574198746681407931124522709494");
            private final BigInteger y = new BigInteger("6186574878464840876340959632109452219062984367530955707919376395905431985630218543528391452506210980290469420037044110204108346208461196604701543348634150850");
            private final BigInteger d = new BigInteger("605023224635491927399374991255922447973305530727544963519573906224953164777982198521510539361376445282339667715822208613069570165965820278992884059022762620");
            private final KeyPair keyPair = createECKeyPair("secp521r1", x, y, d);
            private final byte[] certBytes = Hex.decode("308201a630820107a00302010202141122334455667788990011223344556677"
                                                      + "889900300a06082a8648ce3d040302300f310d300b06035504030c0443657274"
                                                      + "301e170d3236303632353232353730325a170d3336303632323232353730325a"
                                                      + "300f310d300b06035504030c044365727430819b301006072a8648ce3d020106"
                                                      + "052b81040023038186000401a2e4903c21fc3ebc91e107b34b2f0e4ad4e0a38c"
                                                      + "2e4a7b33a9410df2c6df13aaacbd8417b4b0721b03dc4b9fb737430a49d2b6cf"
                                                      + "fc0bc02cf4adf7818f074471f601cd6a7419496cc036bbf98a7114262218f5ce"
                                                      + "3d793e8a3564ecc6515008a80674c234e35959ae54d57d494884af5218b2e9d5"
                                                      + "3a496dadfd0e35af2de94cb95067c2300a06082a8648ce3d04030203818c0030"
                                                      + "8188024201b3bb9260a8c74aa7c8b80f3d7da7d21f7f8051c3450c9a3ed50dde"
                                                      + "3c23553a07073f9442471b5a8151a6a3d55944c5417cbdf462806aef3dbcb218"
                                                      + "c0f73993403d024200ab6bb5d6d2440ce928ace6a38e73af70dd3cc9e82f0702"
                                                      + "5e4855f08fe94573b311c55f7ebdd35cd5e68b9a83a5593325541f0a13c61403"
                                                      + "ab4692e55c51630ff3bc");
            private final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certBytes));

            private final String expectedJwkPub =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-521\",\n" +
                    "  \"x\": \"AaLkkDwh_D68keEHs0svDkrU4KOMLkp7M6lBDfLG3xOqrL2EF7SwchsD3EuftzdDCknSts_8C8As9K33gY8HRHH2\",\n" +
                    "  \"y\": \"Ac1qdBlJbMA2u_mKcRQmIhj1zj15Poo1ZOzGUVAIqAZ0wjTjWVmuVNV9SUiEr1IYsunVOkltrf0ONa8t6Uy5UGfC\"\n" +
                    "}";

            private final String expectedJwk =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-521\",\n" +
                    "  \"x\": \"AaLkkDwh_D68keEHs0svDkrU4KOMLkp7M6lBDfLG3xOqrL2EF7SwchsD3EuftzdDCknSts_8C8As9K33gY8HRHH2\",\n" +
                    "  \"y\": \"Ac1qdBlJbMA2u_mKcRQmIhj1zj15Poo1ZOzGUVAIqAZ0wjTjWVmuVNV9SUiEr1IYsunVOkltrf0ONa8t6Uy5UGfC\",\n" +
                    "  \"d\": \"AC0f6-tlveZ20xe6LbnC5TEoBdLdQiZ-1zhR4PQWwyPeFEqjLDscXAd2qNYPMeZhArIKZU6U2maNWsUG_UVVSyJ8\"\n" +
                    "}";

            private final String expectedJwkCert =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-521\",\n" +
                    "  \"x\": \"AaLkkDwh_D68keEHs0svDkrU4KOMLkp7M6lBDfLG3xOqrL2EF7SwchsD3EuftzdDCknSts_8C8As9K33gY8HRHH2\",\n" +
                    "  \"y\": \"Ac1qdBlJbMA2u_mKcRQmIhj1zj15Poo1ZOzGUVAIqAZ0wjTjWVmuVNV9SUiEr1IYsunVOkltrf0ONa8t6Uy5UGfC\",\n" +
                    "  \"d\": \"AC0f6-tlveZ20xe6LbnC5TEoBdLdQiZ-1zhR4PQWwyPeFEqjLDscXAd2qNYPMeZhArIKZU6U2maNWsUG_UVVSyJ8\",\n" +
                    "  \"exp\": 2097788222,\n" +
                    "  \"nbf\": 1782428222,\n" +
                    "  \"x5c\": [\"MIIBpjCCAQegAwIBAgIUESIzRFVmd4iZABEiM0RVZneImQAwCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwEQ2VydDAeFw0yNjA2MjUyMjU3MDJaFw0zNjA2MjIyMjU3MDJaMA8xDTALBgNVBAMMBENlcnQwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGi5JA8Ifw+vJHhB7NLLw5K1OCjjC5KezOpQQ3yxt8Tqqy9hBe0sHIbA9xLn7c3QwpJ0rbP/AvALPSt94GPB0Rx9gHNanQZSWzANrv5inEUJiIY9c49eT6KNWTsxlFQCKgGdMI041lZrlTVfUlIhK9SGLLp1TpJba39DjWvLelMuVBnwjAKBggqhkjOPQQDAgOBjAAwgYgCQgGzu5JgqMdKp8i4Dz19p9Iff4BRw0UMmj7VDd48I1U6Bwc/lEJHG1qBUaaj1VlExUF8vfRigGrvPbyyGMD3OZNAPQJCAKtrtdbSRAzpKKzmo45zr3DdPMnoLwcCXkhV8I/pRXOzEcVffr3TXNXmi5qDpVkzJVQfChPGFAOrRpLlXFFjD/O8\"],\n" +
                    "  \"x5t\": \"o_ItxlqyWA-_STfIMfl5ZzU7qMQ\",\n" +
                    "  \"x5t#S256\": \"liewIjIn9C1oKs6Nt8yGSuSTzzefl_P9O-uLwECclzg\"\n" +
                    "}";

            ForP521() throws Exception {}

            @Test
            void shouldExportWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias");
                JSONAssert.assertEquals(expectedJwk, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }

            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), null);
                JSONAssert.assertEquals(
                    expectedJwk.replace("alias", "BNyJVIk1Jsf8IYupsfb036JM4dbXJXB_wL-8WXjJr7E"),
                    actualJwk,
                    JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertNull(jwk.getParsedX509CertChain());
            }

            @Test
            void shouldExportWithProvidedCert() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias", new X509Certificate[] {cert});
                JSONAssert.assertEquals(expectedJwkCert, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
                assertArrayEquals(cert.getEncoded(), jwk.getParsedX509CertChain().get(0).getEncoded());
            }

            @Test
            void shouldExportPublicWithProvidedAlias() throws Exception {
                String actualJwk = JwkUtil.get(keyPair.getPublic(), "alias");
                JSONAssert.assertEquals(expectedJwkPub, actualJwk, JSONCompareMode.STRICT);

                JWK jwk = JwkUtil.load(actualJwk.getBytes());
                PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
                PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
                assertNull(actualPrivateKey);
                assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
            }
        }

        @Test
        void throwsJwkExporterExceptionWhenExportingUnsupportedCurve() throws CryptoException {

            KeyPair keyPair = KeyPairUtil.generateECKeyPair("secp128r1", null);
            assertThrows(JwkExporterException.class, () -> JwkUtil.get(keyPair.getPublic(), null));
        }
    }
    @Nested
    class RSAExporter {
        private RSAPrivateCrtKey testRsaPrivateKey;
        private KeyPair keyPair;
        private X509Certificate cert;

        private final String expectedJwkPub =
            "{\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"kid\": \"alias\",\n" +
                "  \"n\": \"mkMScoqwTsTnhdkoRZkZS3PVSlEvauRkokKjmBvLovSoXVCSQzRY0loNV8sTPNjnhP64lFL9yRKqDG1o-SNYjXYOEjGJplApsPd3jAZ8AJMxoMhK46u02PfonKdvGKt53raUF6FsJHMXas2WKklKfAxp-DxmoPSJ2iWkdW5b2H7vE6Vpu02U8VxZ9s8sfWzjbctbJwj6ZeM3g0noBOsqrqwlYrVy5KxsiGX4ydn8tT3b8RSioPxT4XSVtwWNsz_r-z3RKapThDrzjA1uvgVC1Y-_vXYybb_PjqcEEyYUyf3hxojOGJr2_HM-N6lEujxCX2qwifYGjmnYxQ_lG_RGew\"\n" +
                "}";

        private final String expectedJwk =
            "{\n" +
                "  \"p\": \"1aRFSWat1ZsPl3BjZBbuEBtiFIoVOyc2CqpPLkLdUSq4-PjiQY5GamPOhuoJVMil-dmXJz5SSbj9H7Fvu-EJDRDtUhy_mRSLz8wh-8e496jbs2nEYNAjsaJDEB5Bv4Rg1-4YXjfVQcpQUSzoI2hdKjlVNKQuJqAx_Rf2VGsdqz0\",\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"d\": \"NG_nRetR-jyhrNSABYSA3i6eSrhlI3NGqAd5_7s3EgoTb0DzrweMx9hXn8fGntDmhkVl7fl2DlMbXcUVQVccA14lc1bGgTPPsDm2t_D-Vt2yKYLcPh8Ahx5iQloCAENN1oB-v7eeAJfk1mfTC0XFnXxEy16QzlbBw1c3W7mrW-BmpFDeXK0fuxupuxMGuCEZWJ-R0dzGRsPXvWi-uRPoyov-VPzHhk97uQITtuzV2RkqfVf4hDIyMxz5dcL8OWo0U9EntV7r4pEyHJkhrG8JN3_NVgxs3R2xZVMG4ySB_aO3Nbwro8cJewt6XqgqSnuREI-8LPn0HJkZqWI3QN-PXQ\",\n" +
                "  \"q\": \"uNjjuVOlvEoKK0FPByW_xnXhZXCJZ2Xz56BK3AcHoOo7UWeK6tYtWvXOfHO82928F3O4gOTEf_bp5b6QK_d539oCIVrbHrda7Dm8x4Dx_gyxmjUYgFkQGX--6SuDBys4lQ2TrsD_Gr0hne2FFRXjTi4Prw-IiHURSMC7_qmftBc\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"kid\": \"alias\",\n" +
                "  \"qi\": \"mKhdcx_2KSLtpH_jSt32zWsQMAU-jEkTDEkoA890UH_BVEhMWfUNprjE6QQy2q_zizwi89Fh-Ies1QKKbaAG0giaqQGJOQDpO9vcoVFujq4xJCRNHP-WzxStaKNRXd30vVc6KZNIno0NN-0KA2zlUsjHfWxoqkgWXusiPz1_VE8\",\n" +
                "  \"dp\": \"HdPnkI3za0VQ8fXRCqJg7oLEONXmjPG2i9qnX3AackCivrAQ9tIkZqo0pYV7dAjnk3Cbt_DtkDlxrcEaNoL-voJEgBhfb8H8mzCG9h42Zu1-bxgvQM0Ojrh24IM47sJOuxcU8-KbtanHeO3qIzdo-oIysTzS7LWlBQ8ZZ0PlSok\",\n" +
                "  \"dq\": \"hny24qWrVd0AnQv9NZQPfZNSlH1WWzZgSMvk60TqFfeVhNqyxb1ibmWdAAstA0LGkMGPIahQF1JMRu1o87Qwpd914VK7ThPVQT2YzgZRCqetqCatVuR1xDefbQJNaK_XkQq5wlGEya2FgePICdlM8hqtKo9ApReXpbkkjlpXaa0\",\n" +
                "  \"n\": \"mkMScoqwTsTnhdkoRZkZS3PVSlEvauRkokKjmBvLovSoXVCSQzRY0loNV8sTPNjnhP64lFL9yRKqDG1o-SNYjXYOEjGJplApsPd3jAZ8AJMxoMhK46u02PfonKdvGKt53raUF6FsJHMXas2WKklKfAxp-DxmoPSJ2iWkdW5b2H7vE6Vpu02U8VxZ9s8sfWzjbctbJwj6ZeM3g0noBOsqrqwlYrVy5KxsiGX4ydn8tT3b8RSioPxT4XSVtwWNsz_r-z3RKapThDrzjA1uvgVC1Y-_vXYybb_PjqcEEyYUyf3hxojOGJr2_HM-N6lEujxCX2qwifYGjmnYxQ_lG_RGew\"\n" +
            "}";

        private final String expectedJwkCert =
            "{\n" +
                "  \"p\": \"1aRFSWat1ZsPl3BjZBbuEBtiFIoVOyc2CqpPLkLdUSq4-PjiQY5GamPOhuoJVMil-dmXJz5SSbj9H7Fvu-EJDRDtUhy_mRSLz8wh-8e496jbs2nEYNAjsaJDEB5Bv4Rg1-4YXjfVQcpQUSzoI2hdKjlVNKQuJqAx_Rf2VGsdqz0\",\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"d\": \"NG_nRetR-jyhrNSABYSA3i6eSrhlI3NGqAd5_7s3EgoTb0DzrweMx9hXn8fGntDmhkVl7fl2DlMbXcUVQVccA14lc1bGgTPPsDm2t_D-Vt2yKYLcPh8Ahx5iQloCAENN1oB-v7eeAJfk1mfTC0XFnXxEy16QzlbBw1c3W7mrW-BmpFDeXK0fuxupuxMGuCEZWJ-R0dzGRsPXvWi-uRPoyov-VPzHhk97uQITtuzV2RkqfVf4hDIyMxz5dcL8OWo0U9EntV7r4pEyHJkhrG8JN3_NVgxs3R2xZVMG4ySB_aO3Nbwro8cJewt6XqgqSnuREI-8LPn0HJkZqWI3QN-PXQ\",\n" +
                "  \"q\": \"uNjjuVOlvEoKK0FPByW_xnXhZXCJZ2Xz56BK3AcHoOo7UWeK6tYtWvXOfHO82928F3O4gOTEf_bp5b6QK_d539oCIVrbHrda7Dm8x4Dx_gyxmjUYgFkQGX--6SuDBys4lQ2TrsD_Gr0hne2FFRXjTi4Prw-IiHURSMC7_qmftBc\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"kid\": \"alias\",\n" +
                "  \"qi\": \"mKhdcx_2KSLtpH_jSt32zWsQMAU-jEkTDEkoA890UH_BVEhMWfUNprjE6QQy2q_zizwi89Fh-Ies1QKKbaAG0giaqQGJOQDpO9vcoVFujq4xJCRNHP-WzxStaKNRXd30vVc6KZNIno0NN-0KA2zlUsjHfWxoqkgWXusiPz1_VE8\",\n" +
                "  \"dp\": \"HdPnkI3za0VQ8fXRCqJg7oLEONXmjPG2i9qnX3AackCivrAQ9tIkZqo0pYV7dAjnk3Cbt_DtkDlxrcEaNoL-voJEgBhfb8H8mzCG9h42Zu1-bxgvQM0Ojrh24IM47sJOuxcU8-KbtanHeO3qIzdo-oIysTzS7LWlBQ8ZZ0PlSok\",\n" +
                "  \"dq\": \"hny24qWrVd0AnQv9NZQPfZNSlH1WWzZgSMvk60TqFfeVhNqyxb1ibmWdAAstA0LGkMGPIahQF1JMRu1o87Qwpd914VK7ThPVQT2YzgZRCqetqCatVuR1xDefbQJNaK_XkQq5wlGEya2FgePICdlM8hqtKo9ApReXpbkkjlpXaa0\",\n" +
                "  \"n\": \"mkMScoqwTsTnhdkoRZkZS3PVSlEvauRkokKjmBvLovSoXVCSQzRY0loNV8sTPNjnhP64lFL9yRKqDG1o-SNYjXYOEjGJplApsPd3jAZ8AJMxoMhK46u02PfonKdvGKt53raUF6FsJHMXas2WKklKfAxp-DxmoPSJ2iWkdW5b2H7vE6Vpu02U8VxZ9s8sfWzjbctbJwj6ZeM3g0noBOsqrqwlYrVy5KxsiGX4ydn8tT3b8RSioPxT4XSVtwWNsz_r-z3RKapThDrzjA1uvgVC1Y-_vXYybb_PjqcEEyYUyf3hxojOGJr2_HM-N6lEujxCX2qwifYGjmnYxQ_lG_RGew\",\n" +
                "  \"exp\": 2097738611,\n" +
                "  \"nbf\": 1782378611,\n" +
                "  \"x5c\": [\"MIICqjCCAZKgAwIBAgIUESIzRFVmd4iZABEiM0RVZneImQAwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEQ2VydDAeFw0yNjA2MjUwOTEwMTFaFw0zNjA2MjIwOTEwMTFaMA8xDTALBgNVBAMMBENlcnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCaQxJyirBOxOeF2ShFmRlLc9VKUS9q5GSiQqOYG8ui9KhdUJJDNFjSWg1XyxM82OeE/riUUv3JEqoMbWj5I1iNdg4SMYmmUCmw93eMBnwAkzGgyErjq7TY9+icp28Yq3netpQXoWwkcxdqzZYqSUp8DGn4PGag9InaJaR1blvYfu8TpWm7TZTxXFn2zyx9bONty1snCPpl4zeDSegE6yqurCVitXLkrGyIZfjJ2fy1PdvxFKKg/FPhdJW3BY2zP+v7PdEpqlOEOvOMDW6+BULVj7+9djJtv8+OpwQTJhTJ/eHGiM4Ymvb8cz43qUS6PEJfarCJ9gaOadjFD+Ub9EZ7AgMBAAEwDQYJKoZIhvcNAQELBQADggEBADIxWwBi9JXxvFMHJHflXUyZV7Cs8DSHj6T1UGLIp7fZeeeoAE/hxiDWAsxnUUCeIpZcluGT1zvbTEQOELWgGgztMUVLi5ltiOw5Y42hVnWKluUySzvpSz23grnrnTllM5YSbmj7lXruqzScsv+S0gmjqHglg4f6cwfMEuWY/ZZ12UKWXBVbR1/hZo/HOIaWZtacnL3HR75STE3k53QudHsMFMu2SJT4AmKemCxPK8oZfxIgtj3OIzzRGhhxIbZAytJn3pXFt1FvHjYXFuQ7maMWl+eVlXSBdInu79UI4Lmv4pv23b/lD9WxnDEQo2g5YjU4++IWtmcUos++CNkZlpY=\"],\n" +
                "  \"x5t\": \"zWSPONJD89gpN7SJZuoVuO8Qzw0\",\n" +
                "  \"x5t#S256\": \"1OgcuCBxmyOA6RjD4tdZtw6qVH7uguz4iol7t1mg4s0\"\n" +
                "}";

        @BeforeEach
        void beforeEach() throws Exception {
            BigInteger n = new BigInteger(
                "19473773430393612554002103160847019597246845366269418369663587977711596136411467701496403990573007781805455087513725781841939489789080795141324825839726929874391817407362058402748943036071217014898661664868685027183320929392445192622437125252426007342836300982515003688152368515706584800027251796179495311675770645193779164227467469449113506717789119567317874725776614336180021029420774235592891330833310186157561621922409572010502404086401750118640766043929586041675505442508194694394479838887737141862984397494379970163937953777504873086484439901745226134408061711842970315581282680192691917774392510347761398597243");
            BigInteger e = new BigInteger("65537");
            BigInteger d = new BigInteger(
                "6619573486665451632997876820204914461718824444925263099168112381913576802858026331996980940537256524698582872455056320932966217308943763275109690825709395917981654825404096251998711849582320476210460277997347005402695149374249626602474068965789102012298940982009826428777856624634228647673941466490512333580279028190602941883130067638827732470567196743643341793588252999457346441941883243653564360244948992900194565746916243930484811773562590521100975826503672931602283721731074162458391177561660440031754509017802945050826451591599218544278175308070979549582517495348280623940277680309249861631881641415677594013533");
            BigInteger p = new BigInteger(
                "150024291198432876851516748926878492999906807462055104317124882971269292028843049666297032272132140553828537920510214698242263980715739672052842786506445431089010976018678892445174722211305597372102898684180449105243720324348742133342001219176794772072954623652784747126897303746708573839776686524533026171709");
            BigInteger q = new BigInteger(
                "129804135549197193071558452813579053043623129594179350944694847645465292972889455960321266247263910368628101155724971565556824688607276523059939743044453014652531128094749450920887089345782223051712145987856277436384137708183042153395663902406932686945613244956417540122033077739786141296589692818435981947927");
            BigInteger dp = new BigInteger(
                "20945759867947278990362364049024798372661966343863835764555788015733311290780992484346519451455041977318631032434631803239646542007553259979607115011886044440002600524450491567715164078817251567126074171235349639333201717621969124617838948311147476455552356782015967105773995289414887020064340474838292712073");
            BigInteger dq = new BigInteger(
                "94440099352378359705785283840533994647695775902309532199291083287777531768822421519142448040069545053892078052203764197153981946109406276951097041790829739607580286705431181146676506312244807659058830050093275870449798651167795534708821676222093845902936215359444300900236220955925397703648164135811289672109");
            BigInteger qi = new BigInteger(
                "107199865625876623003228922398281553030907252467057844579424881344459608833883125800106058840880807511126863160311432046973616360475652258782063527109486282618781654790355155881977170880089260694592897576540780097975091015548552648217984164496520372155170792210064858287345407929230942686471576867934895559759");

            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            testRsaPrivateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
            PublicKey testRsaPublicKey = keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
            keyPair = new KeyPair(testRsaPublicKey, testRsaPrivateKey);
            byte[] certBytes = Hex.decode("308202aa30820192a00302010202141122334455667788990011223344556677"
                                        + "889900300d06092a864886f70d01010b0500300f310d300b06035504030c0443"
                                        + "657274301e170d3236303632353039313031315a170d33363036323230393130"
                                        + "31315a300f310d300b06035504030c044365727430820122300d06092a864886"
                                        + "f70d01010105000382010f003082010a02820101009a4312728ab04ec4e785d9"
                                        + "284599194b73d54a512f6ae464a242a3981bcba2f4a85d5092433458d25a0d57"
                                        + "cb133cd8e784feb89452fdc912aa0c6d68f923588d760e123189a65029b0f777"
                                        + "8c067c009331a0c84ae3abb4d8f7e89ca76f18ab79deb69417a16c2473176acd"
                                        + "962a494a7c0c69f83c66a0f489da25a4756e5bd87eef13a569bb4d94f15c59f6"
                                        + "cf2c7d6ce36dcb5b2708fa65e3378349e804eb2aaeac2562b572e4ac6c8865f8"
                                        + "c9d9fcb53ddbf114a2a0fc53e17495b7058db33febfb3dd129aa53843af38c0d"
                                        + "6ebe0542d58fbfbd76326dbfcf8ea704132614c9fde1c688ce189af6fc733e37"
                                        + "a944ba3c425f6ab089f6068e69d8c50fe51bf4467b0203010001300d06092a86"
                                        + "4886f70d01010b0500038201010032315b0062f495f1bc53072477e55d4c9957"
                                        + "b0acf034878fa4f55062c8a7b7d979e7a8004fe1c620d602cc6751409e22965c"
                                        + "96e193d73bdb4c440e10b5a01a0ced31454b8b996d88ec39638da156758a96e5"
                                        + "324b3be94b3db782b9eb9d39653396126e68fb957aeeab349cb2ff92d209a3a8"
                                        + "78258387fa7307cc12e598fd9675d942965c155b475fe1668fc738869666d69c"
                                        + "9cbdc747be524c4de4e7742e747b0c14cbb64894f802629e982c4f2bca197f12"
                                        + "20b63dce233cd11a187121b640cad267de95c5b7516f1e361716e43b99a31697"
                                        + "e7959574817489eeefd508e0b9afe29bf6ddbfe50fd5b19c3110a36839623538"
                                        + "fbe216b66714a2cfbe08d9199696");
            cert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certBytes));
        }

        @Test
        void shouldExportWithProvidedAlias() throws Exception {
            String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias");
            JSONAssert.assertEquals(expectedJwk, actualJwk, JSONCompareMode.STRICT);

            JWK jwk = JwkUtil.load(actualJwk.getBytes());
            PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
            PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
            assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
            assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
            assertNull(jwk.getParsedX509CertChain());
        }

        @Test
        void shouldExportAndGenerateAliasIfNotProvided() throws Exception {
            String actualJwk = JwkUtil.get(keyPair.getPrivate(), null);
            JSONAssert.assertEquals(
                expectedJwk.replace("alias", "s9PvqUbQ11Iox4dzumOeuyA0StN3SriANjyZ9cIctEc"),
                actualJwk,
                JSONCompareMode.STRICT);

            JWK jwk = JwkUtil.load(actualJwk.getBytes());
            PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
            PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
            assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
            assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
            assertNull(jwk.getParsedX509CertChain());
        }

        @Test
        void shouldExportWithProvidedCert() throws Exception {
            String actualJwk = JwkUtil.get(keyPair.getPrivate(), "alias", new X509Certificate[] {cert});
            JSONAssert.assertEquals(expectedJwkCert, actualJwk, JSONCompareMode.STRICT);

            JWK jwk = JwkUtil.load(actualJwk.getBytes());
            PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
            PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
            assertArrayEquals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded());
            assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
            assertArrayEquals(cert.getEncoded(), jwk.getParsedX509CertChain().get(0).getEncoded());
        }

        @Test
        void shouldExportPublicWithProvidedAlias() throws Exception {
            String actualJwk = JwkUtil.get(keyPair.getPublic(), "alias");
            JSONAssert.assertEquals(expectedJwkPub, actualJwk, JSONCompareMode.STRICT);

            JWK jwk = JwkUtil.load(actualJwk.getBytes());
            PrivateKey actualPrivateKey = JwkUtil.toPrivateKey(jwk);
            PublicKey actualPublicKey = JwkUtil.toPublicKey(jwk);
            assertNull(actualPrivateKey);
            assertArrayEquals(keyPair.getPublic().getEncoded(), actualPublicKey.getEncoded());
            assertNull(jwk.getParsedX509CertChain());
        }

        @Test
        void shouldThrowIllegalArgumentExceptionWhenKeyIsNotSupported() {
            assertThrows(
                IllegalArgumentException.class,
                () -> JwkUtil.get(new RSAPrivateKey() {

                    @Override
                    public BigInteger getModulus() {
                        return null;
                    }

                    @Override
                    public String getAlgorithm() {
                        return "";
                    }

                    @Override
                    public String getFormat() {
                        return "";
                    }

                    @Override
                    public byte[] getEncoded() {
                        return new byte[0];
                    }

                    @Override
                    public BigInteger getPrivateExponent() {
                        return BigInteger.ZERO;
                    }
                }, null),
                "Expected JwkPrivateKeyExporter.from() to throw, but it didn't"
            );
        }
    }

    @Test
    void handlesUnsupportedPublicKeyTypeWithGrace() {
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
        assertThrows(IllegalArgumentException.class, ()-> JwkUtil.get(unsupportedKey, "testAlias"));
    }
}