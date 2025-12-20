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

package org.kse.crypto.ecc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.kse.KSE;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.utilities.oid.ObjectIdUtil;

/**
 * Unit tests for EccUtil.
 */
public class EccUtilTest extends CryptoTestsBase {

    @ParameterizedTest
    @ValueSource(strings = {
            "JKS",
            "JCEKS",
            "PKCS12",
            "BKS",
            "UBER",
            "PKCS11"
    })
    void testIsEcAvailable(KeyStoreType keyStoreType) {
        assertThat(EccUtil.isECAvailable(keyStoreType)).isTrue();
    }

    @ParameterizedTest
    // @formatter:off
    @ValueSource(strings = {
            // SEC curves
            "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2", "secp192k1",
            /* "secp192r1", = prime192v1 */ "secp224k1", "secp224r1", "secp256k1", /* "secp256r1", = prime256v1 */
            "secp384r1", "secp521r1", "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1", "sect163r1",
            "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1",
            "sect409k1", "sect409r1", "sect571k1", "sect571r1",
            // ANSI X9.62 curves
            "prime192v1", "prime192v2", "prime192v3", "prime239v1", "prime239v2", "prime239v3", "prime256v1",
            "c2pnb163v1", "c2pnb163v2", "c2pnb163v3", "c2pnb176w1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3",
            "c2tnb239v1", "c2tnb239v2", "c2tnb239v3", "c2tnb359v1", "c2tnb431r1", "c2pnb208w1", "c2pnb272w1",
            "c2pnb304w1", "c2pnb368w1",
            // Brainpool curves
            "brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1", "brainpoolP192t1", "brainpoolP224r1",
            "brainpoolP224t1", "brainpoolP256r1", "brainpoolP256t1", "brainpoolP320r1", "brainpoolP320t1",
            "brainpoolP384r1", "brainpoolP384t1", "brainpoolP512r1", "brainpoolP512t1",
            // SM2 curves
            "sm2p256v1", "wapi192v1", "wapip192v1"
            // NIST curves are a subset of SEC curves (not explicitly tested here)
            // Edwards curves are not EC curves (not tested here)
            // GOST curves are EC curves, but GOST is not treated the same as EC (not tested here)
    })
    // @formatter:on
    void convertToECPrivateKeyStructure(String curveName) throws Exception {

        KeyPair keyPair = KeyPairUtil.generateECKeyPair(curveName, KSE.BC);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

        byte[] encoded = EccUtil.convertToECPrivateKeyStructure(ecPrivateKey).toASN1Primitive().getEncoded();

        // @formatter:off
        /*
            verify ASN.1 structure "ECPrivateKey" from RFC 5915:
        
            ECPrivateKey ::= SEQUENCE {
                version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                privateKey     OCTET STRING,
                parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
                publicKey  [1] BIT STRING OPTIONAL
            }
        
            ECParameters ::= CHOICE {
                namedCurve         OBJECT IDENTIFIER
                -- implicitCurve   NULL
                -- specifiedCurve  SpecifiedECDomain
            }
            RFC 5480:
            -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.
        */
        // @formatter:on

        ASN1Sequence sequence = ASN1Sequence.getInstance(encoded);

        // check version of data structure
        BigInteger version = ((ASN1Integer) sequence.getObjectAt(0)).getValue();
        assertThat(version).isEqualTo(BigInteger.ONE);

        // next is an octet string with the key
        assertThat(sequence.getObjectAt(1)).isInstanceOf(ASN1OctetString.class);

        // check for existence of (optional) EC parameters
        ASN1Encodable tagged0 = sequence.getObjectAt(2);
        ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) tagged0;
        assertThat(asn1TaggedObject.getTagNo()).isEqualTo(0);

        // check that EC parameters contain the right curve name
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) asn1TaggedObject.getBaseObject();
        String resolvedCurveName = ObjectIdUtil.toString(oid);
        assertThat(resolvedCurveName).containsIgnoringCase(curveName);
    }

    @ParameterizedTest
    // @formatter:off
    // Only one representative curve is needed to test the getNamedCurve methods.
    @ValueSource(strings = {
            // NIST curve
            "P-384",
            // SEC curve
            "secp160k1", // chosen to not overlap with NIST
            // ANSI X9.62 curve
            "c2pnb163v1", // chosen to not overlap with NIST or SEC
            // Brainpool curve
            "brainpoolP256r1",
            // SM2 curve
            "sm2p256v1",
            // ECGOST curve (not tested here) is handled differently
    })
    // @formatter:on
    void getNamedCurve(String curveName) throws Exception {
        KeyPair ecKeyPair = KeyPairUtil.generateECKeyPair(curveName, KSE.BC);

        assertEquals(curveName, EccUtil.getNamedCurve(ecKeyPair.getPrivate()));
        assertEquals(curveName, EccUtil.getNamedCurve(ecKeyPair.getPublic()));

        KeyPair rsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 2048, KSE.BC);
        assertThrows(InvalidParameterException.class, () -> EccUtil.getNamedCurve(rsaKeyPair.getPublic()));
        assertThrows(InvalidParameterException.class, () -> EccUtil.getNamedCurve(rsaKeyPair.getPrivate()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Ed25519", "Ed448"})
    void detectEDDSACurve(String curveName) throws Exception {
        KeyPair edKeyPair = KeyPairUtil.generateECKeyPair(curveName, KSE.BC);

        assertNotNull(EccUtil.detectEdDSACurve(edKeyPair.getPrivate()));
        assertNotNull(EccUtil.detectEdDSACurve(edKeyPair.getPublic()));
    }

    @Test
    void detectEDDSACurveNotEd() throws Exception {
        KeyPair ecKeyPair = KeyPairUtil.generateECKeyPair("secp384r1", KSE.BC);

        assertThrows(InvalidParameterException.class, () -> EccUtil.detectEdDSACurve(ecKeyPair.getPrivate()));
        assertThrows(InvalidParameterException.class, () -> EccUtil.detectEdDSACurve(ecKeyPair.getPublic()));
    }

}
