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
package org.kse.crypto.privatekey;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import com.nimbusds.jose.JOSEException;

class JwkPrivateKeyExporterTest {
    @Nested
    class EdDSAExporter {
        private byte[] encodePrivateKey(byte[] privateKeyScalar, String curve) throws IOException {
            ASN1ObjectIdentifier oid;
                switch (curve) {
                case "Ed448":
                    oid = new ASN1ObjectIdentifier("1.3.101.113");
                    break;
                case "Ed25519":
                    oid = new ASN1ObjectIdentifier("1.3.101.112");
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

        PrivateKey createEdDSAPrivateKey(String name, byte[] d) {
            try {
                Security.addProvider(new BouncyCastleProvider());
                byte[] pkcs8EncodedKey = encodePrivateKey(d, name);
                KeyFactory keyFactory = KeyFactory.getInstance(name, "BC");
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedKey));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        @Nested
        class ForEd25519{
            byte[] d = Hex.decode("DCAAACEADDAC99D31020B81795E1F64CA36D81701034EE598C161F2655368F76");
            PrivateKey privateKey = createEdDSAPrivateKey("Ed25519", d);
            private final String expectedJwk =
                    "{\n" +
                    "  \"kty\": \"OKP\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"Ed25519\",\n" +
                    "  \"x\": \"FCCz5OTBgteYPnLnFQk5dqSl1fnck5tkMiT1WX_y43w\",\n" +
                    "  \"d\": \"3Kqs6t2smdMQILgXleH2TKNtgXAQNO5ZjBYfJlU2j3Y\"\n" +
                    "}";
            @Test
            void shouldExportWithProvidedAlias() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, "alias");
                JSONAssert.assertEquals(expectedJwk, new String(exporter.get()), JSONCompareMode.STRICT);
            }
            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, null);
                JSONAssert.assertEquals(
                        expectedJwk.replace("alias", "hMKYp7HryDQcWc9sdicmx4x0l7BXvkeZCbMm6fYH_UM"),
                        new String(exporter.get()),
                        JSONCompareMode.STRICT);
            }
        }
        @Nested
        class forEd448{
            byte[] d = Hex.decode("0DAAE3F2A4AC597FD67BEE8F46F50AE24CD67D53F846BE5DEB6ACE0CB67FD9EA95604FBDEF9F566A4245C9A5BAB81FD8DC0AF3179CE94C4084");
            PrivateKey privateKey = createEdDSAPrivateKey("Ed448", d);
            private final String expectedJwk =
                    "{\n" +
                    "  \"kty\": \"OKP\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"Ed448\",\n" +
                    "  \"x\": \"J4amktQFNkPV_ei8-UiGvixoY8saK7__4LL6aLnLWLzLTpFIZdJA17T9hqFfzexgpwE4C7LeA8gA\",\n" +
                    "  \"d\": \"Darj8qSsWX_We-6PRvUK4kzWfVP4Rr5d62rODLZ_2eqVYE-9759WakJFyaW6uB_Y3ArzF5zpTECE\"\n" +
                    "}";
            @Test
            void shouldExportWithProvidedAlias() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, "alias");
                JSONAssert.assertEquals(expectedJwk, new String(exporter.get()), JSONCompareMode.STRICT);
            }
            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, null);
                JSONAssert.assertEquals(
                        expectedJwk.replace("alias", "nH74MmF8qGFGAXy5TjR7fRg2oNadcEM5q0c3X3AZSnU"),
                        new String(exporter.get()),
                        JSONCompareMode.STRICT);
            }
        }
    }
    @Nested
    class ECExporter {
         PrivateKey createECPrivateKey(String name, BigInteger x, BigInteger y, BigInteger d, BigInteger n) {
            try {
                ECCurve curve = null;
                switch (name) {
                    case "secp256r1":
                        curve = new SecP256R1Curve();
                        break;
                    case "secp384r1":
                        curve = new SecP384R1Curve();
                        break;
                    case "secp521r1":
                        curve = new SecP521R1Curve();
                        break;
                default:
                    throw new IllegalArgumentException(name);
                }
                ECPoint ecPoint = curve.createPoint(x, y);
                ECParameterSpec ecParameterSpec = new ECNamedCurveParameterSpec(
                    name,
                    curve,
                    ecPoint,
                    n
                );
                Security.addProvider(new BouncyCastleProvider());
                KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, ecParameterSpec);
                return keyFactory.generatePrivate(ecPrivateKeySpec);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
        @Nested
        class ForP256 {
            private final BigInteger x = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
            private final BigInteger y = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
            private final BigInteger n = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
            private final BigInteger d = new BigInteger("1A2B3C4D5E6F7890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", 16); // Valid scalar
            private final PrivateKey privateKey = createECPrivateKey("secp256r1", x, y, d, n);

            private final String expectedJwk =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-256\",\n" +
                    "  \"x\": \"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY\",\n" +
                    "  \"y\": \"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU\",\n" +
                    "  \"d\": \"Gis8TV5veJASNFZ4mrze8BI0VniavN7wEjRWeJq83vA\"\n" +
                    "}";

            @Test
            void shouldExportWithProvidedAlias() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, "alias");
                JSONAssert.assertEquals(expectedJwk, new String(exporter.get()), JSONCompareMode.STRICT);
            }

            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, null);
                JSONAssert.assertEquals(
                    expectedJwk.replace("alias", "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"),
                    new String(exporter.get()),
                    JSONCompareMode.STRICT);
            }
        }
        @Nested
        class ForP384 {
            private final BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16);
            private final BigInteger x = new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16);
            private final BigInteger y = new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16);
            private final BigInteger d = new BigInteger("09e6f7f2fc01e65c491c0b86cfce1e11c7751fa53a82d9ec00d278a58ad336c01e5750ee016ea484878c826d9864ed74", 16); // Valid scalar
            private final PrivateKey privateKey = createECPrivateKey("secp384r1", x, y, d, n);

            private final String expectedJwk =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-384\",\n" +
                    "  \"x\": \"qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3\",\n" +
                    "  \"y\": \"NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f\",\n" +
                    "  \"d\": \"Ceb38vwB5lxJHAuGz84eEcd1H6U6gtnsANJ4pYrTNsAeV1DuAW6khIeMgm2YZO10\"\n" +
                    "}";

            @Test
            void shouldExportWithProvidedAlias() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, "alias");
                JSONAssert.assertEquals(expectedJwk, new String(exporter.get()), JSONCompareMode.STRICT);
            }

            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, null);
                JSONAssert.assertEquals(
                    expectedJwk.replace("alias", "-W6Wzot_wuerYbKBVKfGEks3iY2EALna-hBqObnPuJE"),
                    new String(exporter.get()),
                    JSONCompareMode.STRICT);
            }
        }
        @Nested
        class ForP521 {
            private final BigInteger n = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16);
            private final BigInteger x = new BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16);
            private final BigInteger y = new BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16);
            private final BigInteger d = new BigInteger("00c29ec3b1705e2b03e030e7ba2f7a674101ea177a8d8fdf3d99983c27d8f47f96961c89d456c4db787d9d0be8abaaed318066c10dd7aad961dad62e9d3b4a3d93c4", 16); // Valid scalar
            private final PrivateKey privateKey = createECPrivateKey("secp521r1", x, y, d, n);

            private final String expectedJwk =
                "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"kid\": \"alias\",\n" +
                    "  \"crv\": \"P-521\",\n" +
                    "  \"x\": \"xoWOBrcEBOnNnj7LZiOVtEKcZIE5BT-1Ifgor2BrTT26oUted-_nWSj-HcEnov-o3jNIs8GFakKb-X5-McLlvWY\",\n" +
                    "  \"y\": \"ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT-tB2E1PHCGonLCQIi-lHaf0WZQ\",\n" +
                    "  \"d\": \"wp7DsXBeKwPgMOe6L3pnQQHqF3qNj989mZg8J9j0f5aWHInUVsTbeH2dC-irqu0xgGbBDdeq2WHa1i6dO0o9k8Q\"\n" +
                    "}";

            @Test
            void shouldExportWithProvidedAlias() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, "alias");
                JSONAssert.assertEquals(expectedJwk, new String(exporter.get()), JSONCompareMode.STRICT);
            }
            @Test
            void shouldExportAndGenerateAliasIfNotProvided() throws JOSEException, JSONException {
                JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(privateKey, null);
                JSONAssert.assertEquals(
                    expectedJwk.replace("alias", "67t2ktf21o_Z2-ygUyR0zriEF9PMHtlT1l4q9rGSYOM"),
                    new String(exporter.get()),
                    JSONCompareMode.STRICT);
            }
        }
    }
    @Nested
    class RSAExporter {
        private RSAPrivateCrtKey testRsaPrivateKey;
        private final String expectedJwk =
            "{\n" +
                "  \"p\": \"uaoJ56P-gRGRcJnkEwX0C0OX3-Nk4XUqG0kwUpxzQx9y4tWhfPVQ3W1JOT8UiNmTEs9JKw\",\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"d\": \"c5Q7yaaHojmwXPNw9UR3nDlaL2RSC_T8QE8499zCJ8yYVadW_gPoQFizfTbvhGODUExqCvSmyCaLoNK2VQ4S1G5t29do054-zXr4bXUVeHxHOtLo3dAJ3Owuuh4QQn_PIWfP3j8eN-ZRs9_z_tCRyZPlNnXxlH_s06FVJvUB7cE\",\n" +
                "  \"q\": \"K4WNfODwFNumkDkmKV1y0uKFcwpRFpvRZDcKZzjjM5HyiBdFm9FOyQ_Vd9Q4IjZ8j1zd\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"kid\": \"alias\",\n" +
                "  \"qi\": \"MyGthx89UnbzoyRhQxkLctJGFg7rW5e2eCl37IdO6IFp_mmGpQHY1ybnzZyWLdIN9GZIKw\",\n" +
                "  \"dp\": \"TZeMvYe1p9dxEdDY6ayAhVcXt2yS6Es8u5uLxRWIThlbkub0DY6cDjUJyiMohQCupcS-hQ\",\n" +
                "  \"dq\": \"FY7qOmK0nWgJs-QNgZFqqN5Lz5aG7j3zKaiyq762vMkOxaCc0loSbKiOO2od3B6-BKAB\",\n" +
                "  \"n\": \"AOlUA-YezpKq4KCQeSa38Y9JlFFeYpvUZDRugvOzFnaq2Y6up7_LiI3n93SRTXGLGxv5dfA3YgB-_xaod4EGQe9sOROg4sf1s4aBzbCjB4gl5iVES9F73tw12D5aLkWlhGw6PfveTxusvhWA9Y80m_i4Jj54Fy4qAD6hgdU4L2Bf\"\n" +
            "}";

        @BeforeEach
        void beforeEach() throws Exception {
            BigInteger n = new BigInteger(
                "163848623215722573335289836290296380412600155169274542756345123525431136485103332108140966186957962358607966816937336373975517262686919727031911213273434467263220165629066576551436849585929539697852639506556574744932441880932740785492524179462275479949333856745765569341268928807012350302362205570952334368863");
            BigInteger e = new BigInteger("65537");
            BigInteger d = new BigInteger(
                "81162360104056367444041882273685533022608067258951749282561205052664337647413783849573620812056810889784984274619756416027199837912278433433854087061507142355364653690001337610110670204774550710530299556779525306616051247642876289624719232867435836251485874089121819535380161331921146955132661141083099622849");
            BigInteger p = new BigInteger(
                "122734436614797484015276528291786391292815307418847457882419065193890573226768384141673744961572404667732960146628556486560043");
            BigInteger q = new BigInteger(
                "112383879168171019021288484133164825686900629756358597762781058537871128411671231241861769924742254727413603248493558717661");
            BigInteger dp = new BigInteger(
                "51292648964209133170344456603196539129849777424887014274422094802525675770368384598278293051187555434638021173107662275264133");
            BigInteger dq = new BigInteger(
                "55668818224887815696812473861368312212583125550674272064933768218054019051908255830472755309012818345502448274493724205057");
            BigInteger qi = new BigInteger(
                "33800819014409014162527712312738217473191730864466927822214453530136540809553950561832440871643016047324557330030961453582379");

            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi);
            new String(Base64.getUrlDecoder().decode("OznnOoln2izFB_uABhJRHplqqzLLrW7CRbTIjfd0Bdg"));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            testRsaPrivateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
        }

        @Test
        void shouldExportWithProvidedAlias() throws JOSEException, JSONException {
            JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(testRsaPrivateKey, "alias");
            JSONAssert.assertEquals(expectedJwk, new String(exporter.get()), JSONCompareMode.STRICT);
        }

        @Test
        void shouldExportAndGenerateAliasIfNotProvided() throws JOSEException, JSONException {
            JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(testRsaPrivateKey, null);
            JSONAssert.assertEquals(
                expectedJwk.replace("alias", "VvKXLBWz54q6mlHpf_WR6AFLSOd2UV53kASJK2UWYH4"),
                new String(exporter.get()),
                JSONCompareMode.STRICT);
        }

        @Test
        void shouldThrowIllegalArgumentExceptionWhenKeyIsNotSupported() {
            assertThrows(
                IllegalArgumentException.class,
                () -> JwkPrivateKeyExporter.from(new RSAPrivateKey() {

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
}