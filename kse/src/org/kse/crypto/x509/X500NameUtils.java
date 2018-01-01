/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
package org.kse.crypto.x509;

import java.io.IOException;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Utility class that handles distinguished names.
 */
public class X500NameUtils {

	/**
	 * Convert an X.500 Principal to an X.500 Name.
	 *
	 * @param principal
	 *            X.500 Principal
	 * @return X.500 Name
	 */
	public static X500Name x500PrincipalToX500Name(X500Principal principal) {
		return X500Name.getInstance(KseX500NameStyle.INSTANCE, principal.getEncoded());
	}


	/**
	 * Convert an X.500 Name to an X.500 Principal.
	 *
	 * @param name
	 *            X.500 Name
	 * @return X.500 Principal
	 * @throws IOException if an encoding error occurs (incorrect form for DN)
	 */
	public static X500Principal x500NameToX500Principal(X500Name name) throws IOException {
		return new X500Principal(name.getEncoded());
	}


	/**
	 * Returns the (first) value of the (first) RDN of type rdnOid
	 *
	 * @param dn The X500Name
	 * @param rdnOid OID of wanted RDN
	 * @return Value of requested RDN
	 */
	public static String getRdn(X500Name dn, ASN1ObjectIdentifier rdnOid) {

		if (dn == null || rdnOid == null) {
			return "";
		}

		RDN[] rdns = dn.getRDNs(rdnOid);
		String value = "";

		if (rdns.length > 0) {
			RDN rdn = rdns[0];
			value = rdn.getFirst().getValue().toString();
		}

		return value;
	}

	/**
	 * Creates an X500Name object from the given components.
	 *
	 * @param commonName
	 * @param organisationUnit
	 * @param organisationName
	 * @param localityName
	 * @param stateName
	 * @param countryCode
	 * @param emailAddress
	 * @return X500Name object from the given components
	 */
	public static X500Name buildX500Name(String commonName, String organisationUnit, String organisationName,
			String localityName, String stateName, String countryCode, String emailAddress) {

		X500NameBuilder x500NameBuilder = new X500NameBuilder(KseX500NameStyle.INSTANCE);

		if (emailAddress != null) {
			x500NameBuilder.addRDN(BCStyle.E, emailAddress);
		}
		if (countryCode != null) {
			x500NameBuilder.addRDN(BCStyle.C, countryCode);
		}
		if (stateName != null) {
			x500NameBuilder.addRDN(BCStyle.ST, stateName);
		}
		if (localityName != null) {
			x500NameBuilder.addRDN(BCStyle.L, localityName);
		}
		if (organisationName != null) {
			x500NameBuilder.addRDN(BCStyle.O, organisationName);
		}
		if (organisationUnit != null) {
			x500NameBuilder.addRDN(BCStyle.OU, organisationUnit);
		}
		if (commonName != null) {
			x500NameBuilder.addRDN(BCStyle.CN, commonName);
		}

		return x500NameBuilder.build();
	}
}
