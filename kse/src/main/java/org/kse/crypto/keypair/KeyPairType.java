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
package org.kse.crypto.keypair;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Enumeration of Key Pair Types supported by the KeyPairUtil class.
 */
public enum KeyPairType {
    RSA("RSA", "1.2.840.113549.1.1.1", 512, 16384, 8),
    DSA("DSA", "1.2.840.10040.4.1", 512, 2048, 64),
    EC("EC", "1.2.840.10045.2.1", 160, 571, 32),
    ECDSA("ECDSA", "1.2.840.10045.2.1", 160, 571, 32),
    EDDSA("EdDSA", "", 256, 456, 200), // for Java >= 15 (there is no specific OID for EdDSA)
    ED25519("Ed25519", "1.3.101.112", 256, 256, 0), // BC has separate key pair types for the two EdDSA types
    ED448("Ed448", "1.3.101.113", 456, 456, 0),
    ECGOST3410("ECGOST3410", "1.2.643.2.2.19", 256, 256, 0),
    ECGOST3410_2012("ECGOST3410-2012", "", 256, 512, 256), // There are two OIDs: One for 256-bit, one for 512-bit.

    MLDSA44("ML-DSA-44", "2.16.840.1.101.3.4.3.17", 10_496, 10_496, 0),
    MLDSA65("ML-DSA-65", "2.16.840.1.101.3.4.3.18", 15_616, 15_616, 0),
    MLDSA87("ML-DSA-87", "2.16.840.1.101.3.4.3.19", 20_736, 20_736, 0),

    MLKEM512("ML-KEM-512", "2.16.840.1.101.3.4.4.1", 13_056, 13_056, 0),
    MLKEM768("ML-KEM-768", "2.16.840.1.101.3.4.4.2", 19_200, 19_200, 0),
    MLKEM1024("ML-KEM-1024", "2.16.840.1.101.3.4.4.3", 25_344, 25_344, 0),

    SLHDSA_SHA2_128S("SLH-DSA-SHA2-128S", "2.16.840.1.101.3.4.3.20", 512, 512, 0),
    SLHDSA_SHA2_128F("SLH-DSA-SHA2-128F", "2.16.840.1.101.3.4.3.21", 512, 512, 0),
    SLHDSA_SHA2_192S("SLH-DSA-SHA2-192S", "2.16.840.1.101.3.4.3.22", 768, 768, 0),
    SLHDSA_SHA2_192F("SLH-DSA-SHA2-192F", "2.16.840.1.101.3.4.3.23", 768, 768, 0),
    SLHDSA_SHA2_256S("SLH-DSA-SHA2-256S", "2.16.840.1.101.3.4.3.24", 1024, 1024, 0),
    SLHDSA_SHA2_256F("SLH-DSA-SHA2-256F", "2.16.840.1.101.3.4.3.25", 1024, 1024, 0),
    SLHDSA_SHAKE_128S("SLH-DSA-SHAKE-128S", "2.16.840.1.101.3.4.3.26", 512, 512, 0),
    SLHDSA_SHAKE_128F("SLH-DSA-SHAKE-128F", "2.16.840.1.101.3.4.3.27", 512, 512, 0),
    SLHDSA_SHAKE_192S("SLH-DSA-SHAKE-192S", "2.16.840.1.101.3.4.3.28", 768, 768, 0),
    SLHDSA_SHAKE_192F("SLH-DSA-SHAKE-192F", "2.16.840.1.101.3.4.3.29", 768, 768, 0),
    SLHDSA_SHAKE_256S("SLH-DSA-SHAKE-256S", "2.16.840.1.101.3.4.3.30", 1024, 1024, 0),
    SLHDSA_SHAKE_256F("SLH-DSA-SHAKE-256F", "2.16.840.1.101.3.4.3.31", 1024, 1024, 0);

    /**
     * Set of all EC key pair types (EC, ECDSA, EDDSA, ED25519, ED448)
     */
    public static final Set<KeyPairType> EC_TYPES_SET = EnumSet.of(EC, ECDSA, EDDSA, ED25519, ED448, ECGOST3410, ECGOST3410_2012);

    /**
     * Set of all ML-DSA key pair types
     */
    public static final Set<KeyPairType> MLDSA_TYPES_SET = EnumSet.of(MLDSA44, MLDSA65, MLDSA87);

    /**
     * Set of all ML-KEM key pair types
     */
    public static final Set<KeyPairType> MLKEM_TYPES_SET = EnumSet.of(MLKEM512, MLKEM768, MLKEM1024);

    /**
     * List of all SLH-DSA key pair types ordered by their OIDs (.3.20 to .3.31)
     */
    public static final List<KeyPairType> SLHDSA_TYPES_SET =
            Arrays.asList(SLHDSA_SHA2_128S, SLHDSA_SHA2_128F, SLHDSA_SHA2_192S, SLHDSA_SHA2_192F, SLHDSA_SHA2_256S,
                          SLHDSA_SHA2_256F, SLHDSA_SHAKE_128S, SLHDSA_SHAKE_128F, SLHDSA_SHAKE_192S, SLHDSA_SHAKE_192F,
                          SLHDSA_SHAKE_256S, SLHDSA_SHAKE_256F);

    private final String jce;
    private final String oid;
    private final int minSize;
    private final int maxSize;
    private final int stepSize;

    KeyPairType(String jce, String oid, int minSize, int maxSize, int stepSize) {
        this.jce = jce;
        this.oid = oid;
        this.minSize = minSize;
        this.maxSize = maxSize;
        this.stepSize = stepSize;
    }

    /**
     * Get key pair type JCE name.
     *
     * @return JCE name
     */
    public String jce() {
        return jce;
    }

    /**
     * Get key pair type Object Identifier.
     *
     * @return Object Identifier
     */
    public String oid() {
        return oid;
    }

    /**
     * Get key pair minimum size.
     *
     * @return Minimum size
     */
    public int minSize() {
        return minSize;
    }

    /**
     * Get key pair maximum size.
     *
     * @return Maximum size
     */
    public int maxSize() {
        return maxSize;
    }

    /**
     * Get key pair step size.
     *
     * @return Step size
     */
    public int stepSize() {
        return stepSize;
    }

    /**
     * Resolve the supplied JCE name to a matching KeyPair type.
     *
     * @param jce JCE name
     * @return KeyPair type or null if none
     */
    public static KeyPairType resolveJce(String jce) {
        for (KeyPairType keyPairType : values()) {
            if (jce.equals(keyPairType.jce())) {
                return keyPairType;
            }
        }

        return null;
    }

    /**
     *
     * @param keyPairType The KeyPairType to check.
     * @return True if keyPairType is a ML-DSA key type.
     */
    public static boolean isMlDSA(KeyPairType keyPairType) {
        return MLDSA_TYPES_SET.contains(keyPairType);
    }

    /**
     *
     * @param keyPairType The KeyPairType to check.
     * @return True if keyPairType is a ML-KEM key type.
     */
    public static boolean isMlKEM(KeyPairType keyPairType) {
        return MLKEM_TYPES_SET.contains(keyPairType);
    }

    /**
     *
     * @param keyPairType The KeyPairType to check.
     * @return True if keyPairType is a SLH-DSA key type.
     */
    public static boolean isSlhDsa(KeyPairType keyPairType) {
        return SLHDSA_TYPES_SET.contains(keyPairType);
    }

    /**
     * Gets the ECGOST key pair type for the given curve name.
     *
     * @param curveName The ECGOST curve name.
     * @return The ECGOST key pair type.
     */
    public static KeyPairType getGostTypeFromCurve(String curveName) {
        if (curveName.startsWith("Tc26")) {
            return KeyPairType.ECGOST3410_2012;
        } else {
            return KeyPairType.ECGOST3410;
        }
    }

    /**
     * Returns JCE name.
     *
     * @return JCE name
     */
    @Override
    public String toString() {
        return jce();
    }
}
