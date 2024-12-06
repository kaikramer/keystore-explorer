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
package org.kse.crypto.ocsp;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.CertificateID;

/**
 * Enumeration of Digest Types supported by the DigestUtil class.
 */
public enum OcspDigestAlgorithm {

    // @formatter:off

	SHA1(CertificateID.HASH_SHA1, "SHA-1"),

	SHA256(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), "SHA-256"),
	SHA384(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384), "SHA-384"),
	SHA512(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512), "SHA-512");

	// @formatter:on

    private AlgorithmIdentifier algorithmIdentifier;
    private String friendly;

    OcspDigestAlgorithm(AlgorithmIdentifier algorithmIdentifier, String friendly) {
        this.algorithmIdentifier = algorithmIdentifier;
        this.friendly = friendly;
    }

    /**
     * Get algorithm identifier.
     *
     * @return algorithm identifier
     */
    public AlgorithmIdentifier algorithmIdentifier() {
        return algorithmIdentifier;
    }

    /**
     * Get digest algorithm friendly name.
     *
     * @return Friendly name
     */
    public String friendly() {
        return friendly;
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
