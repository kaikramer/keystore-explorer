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

import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 * X.500 name style. Supports the same DN components as the BC versions but
 * implements the reverse ordering of DN components as the RFC 4519 style.
 *
 */
public class KseX500NameStyle extends BCStyle {
	public static final KseX500NameStyle INSTANCE = new KseX500NameStyle();

	private static final ASN1ObjectIdentifier DNQ = new ASN1ObjectIdentifier("2.5.4.46");

	private static final Hashtable<ASN1ObjectIdentifier, String> DefaultSymbols = new Hashtable<ASN1ObjectIdentifier, String>();

	static {
		DefaultSymbols.put(C, "C");
		DefaultSymbols.put(O, "O");
		DefaultSymbols.put(T, "T");
		DefaultSymbols.put(OU, "OU");
		DefaultSymbols.put(CN, "CN");
		DefaultSymbols.put(L, "L");
		DefaultSymbols.put(ST, "ST");
		DefaultSymbols.put(SN, "SERIALNUMBER");
		DefaultSymbols.put(EmailAddress, "E");
		DefaultSymbols.put(DC, "DC");
		DefaultSymbols.put(UID, "UID");
		DefaultSymbols.put(STREET, "STREET");
		DefaultSymbols.put(SURNAME, "SURNAME");
		DefaultSymbols.put(GIVENNAME, "GIVENNAME");
		DefaultSymbols.put(INITIALS, "INITIALS");
		DefaultSymbols.put(GENERATION, "GENERATION");
		DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
		DefaultSymbols.put(UnstructuredName, "unstructuredName");
		DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
		DefaultSymbols.put(DN_QUALIFIER, "DN");
		DefaultSymbols.put(PSEUDONYM, "Pseudonym");
		DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
		DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
		DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
		DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
		DefaultSymbols.put(GENDER, "Gender");
		DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
		DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
		DefaultSymbols.put(POSTAL_CODE, "PostalCode");
		DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
		DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
		DefaultSymbols.put(NAME, "Name");
	}

	private KseX500NameStyle() {
	}

	@Override
	public ASN1ObjectIdentifier attrNameToOID(String attrName) {
		// Add support for 'DNQ', BCStyle only supports 'DN'
		if (attrName.equalsIgnoreCase("DNQ")) {
			return DNQ;
		}

		return super.attrNameToOID(attrName);
	}

	@Override
	public RDN[] fromString(String name) {
		// Parse backwards
		RDN[] tmp = IETFUtils.rDNsFromString(name, this);
		RDN[] res = new RDN[tmp.length];

		for (int i = 0; i != tmp.length; i++) {
			res[res.length - i - 1] = tmp[i];
		}

		return res;
	}

	@Override
	public String toString(X500Name name) {
		// Convert in reverse
		StringBuffer buf = new StringBuffer();
		boolean first = true;

		RDN[] rdns = name.getRDNs();

		for (int i = rdns.length - 1; i >= 0; i--) {
			if (first) {
				first = false;
			} else {
				buf.append(',');
			}

			if (rdns[i].isMultiValued()) {
				AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();
				boolean firstAtv = true;

				for (int j = 0; j != atv.length; j++) {
					if (firstAtv) {
						firstAtv = false;
					} else {
						buf.append('+');
					}

					IETFUtils.appendTypeAndValue(buf, atv[j], DefaultSymbols);
				}
			} else {
				IETFUtils.appendTypeAndValue(buf, rdns[i].getFirst(), DefaultSymbols);
			}
		}

		return buf.toString();
	}
}
