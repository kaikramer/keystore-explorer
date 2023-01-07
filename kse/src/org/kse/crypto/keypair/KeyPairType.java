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
package org.kse.crypto.keypair;

import java.util.EnumSet;

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
    ED448("Ed448", "1.3.101.113", 456, 456, 0);

    /**
     * Set of all EC key pair types (EC, ECDSA, EDDSA, ED25519, ED448)
     */
    public static final EnumSet<KeyPairType> EC_TYPES_SET = EnumSet.of(EC, ECDSA, EDDSA, ED25519, ED448);

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
     * Returns JCE name.
     *
     * @return JCE name
     */
    @Override
    public String toString() {
        return jce();
    }
}
