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

import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;

/**
 * Provide something like BC's SECNamedCurves/NISTNamedCurves/X962NamedCurves for Ed25519 and Ed448.
 */
public enum EdDSACurves {

    ED25519("Ed25519", EdECObjectIdentifiers.id_Ed25519, 256),
    ED448("Ed448", EdECObjectIdentifiers.id_Ed448, 456);

    private String jce;
    private ASN1ObjectIdentifier oid;
    private int bitLength;

    EdDSACurves(String jce, ASN1ObjectIdentifier oid, int bitLength) {
        this.jce = jce;
        this.oid = oid;
        this.bitLength = bitLength;
    }

    public ASN1ObjectIdentifier oid() {
        return oid;
    }

    public String jce() {
        return jce;
    }

    public int bitLength() {
        return bitLength;
    }

    /**
     * returns an enumeration containing the jce strings for curves contained in this structure.
     */
    public static Enumeration<String> getNames() {
        return Collections.enumeration(Arrays.asList(ED25519.jce, ED448.jce));
    }

    public static EdDSACurves resolve(ASN1ObjectIdentifier oid) {
        return Arrays.stream(EdDSACurves.values()).filter(e -> e.oid.equals(oid)).findFirst()
                     .orElseThrow(() -> new InvalidParameterException("Unknown OID: " + oid.getId()));
    }
}
