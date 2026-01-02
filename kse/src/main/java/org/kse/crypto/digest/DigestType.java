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
package org.kse.crypto.digest;

import java.util.List;

/**
 * Enumeration of Digest Types supported by the DigestUtil class.
 */
public enum DigestType {

    // @formatter:off

    MD5("MD5", "1.2.840.113549.2.5", "MD5"),

    GOST3411("GOST3411", "1.2.643.2.2.9", "GOST-3411"),
    GOST3411_2012_256("GOST3411-2012-256", "1.2.643.7.1.1.2.2", "GOST-3411-2012-256"),
    GOST3411_2012_512("GOST3411-2012-512", "1.2.643.7.1.1.2.3", "GOST-3411-2012-512"),

    RIPEMD160("RIPEMD160", "1.3.36.3.2.1", "RIPEMD-160"),

    SHA1("SHA1", "1.3.14.3.2.26", "SHA-1"),

    SHA224("SHA-224", "2.16.840.1.101.3.4.2.4", "SHA-224"),
    SHA256("SHA-256", "2.16.840.1.101.3.4.2.1", "SHA-256"),
    SHA384("SHA-384", "2.16.840.1.101.3.4.2.2", "SHA-384"),
    SHA512("SHA-512", "2.16.840.1.101.3.4.2.3", "SHA-512"),

    SHA3_224("SHA3-224", "2.16.840.1.101.3.4.2.7", "SHA3-224"),
    SHA3_256("SHA3-256", "2.16.840.1.101.3.4.2.8", "SHA3-256"),
    SHA3_384("SHA3-384", "2.16.840.1.101.3.4.2.9", "SHA3-384"),
    SHA3_512("SHA3-512", "2.16.840.1.101.3.4.2.10", "SHA3-512"),

    SHAKE128("SHAKE128-256", "2.16.840.1.101.3.4.2.11", "SHAKE128"),
    SHAKE256("SHAKE256-512", "2.16.840.1.101.3.4.2.12", "SHAKE256"),

    SM3("SM3", "1.2.156.10197.1.401", "SM3");

    // @formatter:on

    /**
     * List of fingerprint algorithms. GOST, SHAKE, and SM3 are not typically used.
     * If GOST is added to this list then the DViewCertificate layout will need to be
     * adjusted to account for the additional width of the GOST algorithm names.
     */
    public static final List<DigestType> FINGERPRINT_ALGS = List.of(MD5, RIPEMD160, SHA1, SHA224, SHA256, SHA384,
            SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512);

    private String jce;
    private String oid;
    private String friendly;

    DigestType(String jce, String oid, String friendly) {
        this.jce = jce;
        this.oid = oid;
        this.friendly = friendly;
    }

    /**
     * Get digest type JCE name.
     *
     * @return JCE name
     */
    public String jce() {
        return jce;
    }

    /**
     * Get digest type Object Identifier.
     *
     * @return Object Identifier
     */
    public String oid() {
        return oid;
    }

    /**
     * Get signature type friendly name.
     *
     * @return Friendly name
     */
    public String friendly() {
        return friendly;
    }

    /**
     * Resolve the supplied JCE name to a matching Digest type.
     *
     * @param jce JCE name
     * @return Digest type or null if none
     */
    public static DigestType resolveJce(String jce) {
        for (DigestType digestType : values()) {
            if (jce.equals(digestType.jce())) {
                return digestType;
            }
        }

        return null;
    }

    /**
     * Resolve the supplied OID to a matching Digest type.
     *
     * @param oid OID of algorithm
     * @return Digest type or null if none
     */
    public static DigestType resolveOid(String oid) {
        for (DigestType digestType : values()) {
            if (oid.equals(digestType.oid())) {
                return digestType;
            }
        }

        return null;
    }

    /**
     * Returns friendly name.
     *
     * @return Friendly name
     */
    @Override
    public String toString() {
        return friendly();
    }
}
