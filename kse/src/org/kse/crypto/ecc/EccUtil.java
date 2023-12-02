/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.version.JavaVersion;

/**
 * Static helper methods for ECC stuff, mainly detection of available ECC algorithms.
 */
public class EccUtil {

    private static boolean sunECProviderAvailable = true;
    private static String[] availableSunCurves = new String[0];

    static {
        // read available curves provided by SunEC
        Provider sunECProvider = Security.getProvider("SunEC");
        if (sunECProvider != null) {
            availableSunCurves = sunECProvider.getProperty("AlgorithmParameters.EC SupportedCurves").split("\\|");
        } else {
            sunECProviderAvailable = false;
        }
    }

    private EccUtil() {
    }

    /**
     * Determines the name of the domain parameters that were used for generating the key.
     *
     * @param key An EC key
     * @return The name of the domain parameters that were used for the EC key,
     *         or an empty string if curve is unknown.
     */
    public static String getNamedCurve(Key key) {

        if (!(key instanceof ECKey)) {
            throw new InvalidParameterException("Not a EC key.");
        }

        ECKey ecKey = (ECKey) key;
        ECParameterSpec params = ecKey.getParams();
        if (params instanceof ECNamedCurveSpec) {
            ECNamedCurveSpec ecPrivateKeySpec = (ECNamedCurveSpec) params;
            return ecPrivateKeySpec.getName();
        }

        if (key instanceof PublicKey) {
            return getNamedCurve((PublicKey) key);
        }

        return "";
    }

    /**
     * Determines the name of the domain parameters that were used for generating the key.
     *
     * @param publicKey An EC key
     * @return The name of the domain parameters that were used for the EC key,
     *         or an empty string if curve is unknown.
     */
    public static String getNamedCurve(PublicKey publicKey) {

        if (!(publicKey instanceof ECPublicKey)) {
            throw new InvalidParameterException("Not a EC private key.");
        }

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        ASN1Encodable parameters = subjectPublicKeyInfo.getAlgorithm().getParameters();

        /*
         * ECParameters ::= CHOICE {
         *        namedCurve         OBJECT IDENTIFIER
         *        -- implicitCurve   NULL
         *        -- specifiedCurve  SpecifiedECDomain
         *      }
         */
        if (parameters instanceof ASN1ObjectIdentifier) {
            ASN1ObjectIdentifier curveId = ASN1ObjectIdentifier.getInstance(parameters);

            String curveName = NISTNamedCurves.getName(curveId);
            if (curveName == null) {
                curveName = X962NamedCurves.getName(curveId);
            }
            if (curveName == null) {
                curveName = SECNamedCurves.getName(curveId);
            }
            if (curveName == null) {
                curveName = TeleTrusTNamedCurves.getName(curveId);
            }

            if (curveName != null) {
                return curveName;
            }
        } else if (parameters instanceof ASN1Sequence) {
            // RFC 5480: "specifiedCurve, which is of type SpecifiedECDomain type (defined
            //        in [X9.62]), allows all the elliptic curve domain parameters
            //        to be explicitly specified.  This choice MUST NOT be used."
            return "explicitly specified curve";
        }

        return "";
    }

    /**
     * Checks if EC curves are available for the given keyStoreType
     * (i.e. either BC key store type or at least Java 7)
     *
     * @param keyStoreType Availability depends on store type
     * @return True, if there are EC curves available
     */
    public static boolean isECAvailable(KeyStoreType keyStoreType) {
        return ((JavaVersion.getJreVersion().isAtLeast(JavaVersion.JRE_VERSION_170) && sunECProviderAvailable) ||
                isBouncyCastleKeyStore(keyStoreType));
    }

    /**
     * Is the given KeyStoreType backed by the BC provider?
     *
     * @param keyStoreType KeyStoreType to check
     * @return True, if KeyStoreType is backed by the BC provider
     */
    public static boolean isBouncyCastleKeyStore(KeyStoreType keyStoreType) {
        return (keyStoreType == KeyStoreType.BKS || keyStoreType == KeyStoreType.UBER ||
                keyStoreType == KeyStoreType.BCFKS);
    }

    /**
     * Checks if the given named curve is known by the provider backing the KeyStoreType.
     *
     * @param curveName    Name of the curve
     * @param keyStoreType KeyStoreType
     * @return True, if named curve is supported by the keystore
     */
    public static boolean isCurveAvailable(String curveName, KeyStoreType keyStoreType) {

        // BC provides all curves
        if (isBouncyCastleKeyStore(keyStoreType) || EdDSACurves.ED25519.jce().equalsIgnoreCase(curveName) ||
            EdDSACurves.ED448.jce().equalsIgnoreCase(curveName)) {
            return true;
        }

        // no SunEC provider found?
        if (availableSunCurves.length == 0) {
            return false;
        }

        // is curve among SunEC curves?
        for (String curve : availableSunCurves) {
            if (curve.contains(curveName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Finds the longest curve name in all curves that are provided by BC.
     *
     * @return String with the longest curve name
     */
    public static String findLongestCurveName() {
        String longestCurveName = "";
        for (CurveSet curveSet : CurveSet.values()) {
            List<String> curveNames = curveSet.getAllCurveNames();
            for (String curveName : curveNames) {
                if (curveName.length() > longestCurveName.length()) {
                    longestCurveName = curveName;
                }
            }
        }
        return longestCurveName;
    }

    /**
     * Converts PKCS#8 EC private key (RFC 5208/5958 ASN.1 PrivateKeyInfo structure) to "traditional" OpenSSL
     * ASN.1 structure ECPrivateKey from RFC 5915. As ECPrivateKey is already in the PrivateKey field of PrivateKeyInfo,
     * it must only be extracted:
     * <p>
     * <pre>
     * SEQUENCE {
     *      INTEGER 0
     *      SEQUENCE {
     *          OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
     *          OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
     *      }
     *      OCTET STRING, encapsulates {
     *          SEQUENCE {
     *              INTEGER 1
     *              OCTET STRING
     *                  17 12 CA 42 16 79 1B 45    ...B.y.E
     *                  ...
     *                  C8 B2 66 0A E5 60 50 0B
     *              [0] {
     *                  OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
     *              }
     *              [1] {
     *                  BIT STRING
     *                      04 61 C0 08 B4 89 A0 50    .a.....P
     *                      ...
     *                      AE D5 ED C3 4D 0E 47 91    ....M.G.
     *                      89                         .
     *              }
     *          }
     *      }
     * }
     *
     * @param ecPrivateKey An EC key
     * @return Object holding ASN1 ECPrivateKey structure
     * @throws IOException When ECPrivateKey structure in PrivateKeyInfo's PrivateKey field cannot be parsed
     */
    public static org.bouncycastle.asn1.sec.ECPrivateKey convertToECPrivateKeyStructure(ECPrivateKey ecPrivateKey)
            throws IOException {
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(ecPrivateKey.getEncoded());
        ASN1Encodable privateKey = privateKeyInfo.parsePrivateKey();

        return org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(privateKey);
    }

    /**
     * Detect which one of the two EdDSA curves (Ed25519 or Ed448) the given privateKey is.
     *
     * @param privateKey An EdDSA private key
     * @return Ed25519 or Ed448
     * @throws InvalidParameterException if privateKey is not a EdDSA key
     */
    public static EdDSACurves detectEdDSACurve(PrivateKey privateKey) {
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        AlgorithmIdentifier algorithm = privateKeyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOid = algorithm.getAlgorithm();

        return EdDSACurves.resolve(algOid);
    }

    /**
     * Detect which one of the two EdDSA curves (Ed25519 or Ed448) the given publicKey is.
     *
     * @param publicKey An EdDSA public key
     * @return Ed25519 or Ed448
     * @throws InvalidParameterException if publicKey is not a EdDSA key
     */
    public static EdDSACurves detectEdDSACurve(PublicKey publicKey) {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        AlgorithmIdentifier algorithm = publicKeyInfo.getAlgorithm();
        ASN1ObjectIdentifier algOid = algorithm.getAlgorithm();

        return EdDSACurves.resolve(algOid);
    }
}
