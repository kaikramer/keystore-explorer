package org.kse.crypto.ecc;

import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;

/**
 * Provide something like BC's SECNamedCurves/NISTNamedCurves/X962NamedCurves for Ed25519 and Ed448.
 *
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
		return Arrays.stream(EdDSACurves.values())
	            .filter(e -> e.oid.equals(oid))
	            .findFirst()
	            .orElseThrow(() -> new InvalidParameterException("Unknown OID: " + oid.getId()));
	}
}
