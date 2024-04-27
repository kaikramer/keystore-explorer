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

package org.kse.crypto.x509;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 * X.500 name style. Supports the same DN components as the BC versions but
 * implements the reverse ordering of DN components as the RFC 4519 style.
 */
public class KseX500NameStyle extends BCStyle {
    public static final KseX500NameStyle INSTANCE = new KseX500NameStyle();

    private static final ASN1ObjectIdentifier DNQ = new ASN1ObjectIdentifier("2.5.4.46");

    private static final Hashtable<ASN1ObjectIdentifier, String> DEFAULT_SYMBOLS = new Hashtable<>();
    private static final Hashtable<String, ASN1ObjectIdentifier> DEFAULT_LOOKUP = new Hashtable<>();

    static {
        DEFAULT_SYMBOLS.put(C, "C");
        DEFAULT_SYMBOLS.put(O, "O");
        DEFAULT_SYMBOLS.put(T, "T");
        DEFAULT_SYMBOLS.put(OU, "OU");
        DEFAULT_SYMBOLS.put(CN, "CN");
        DEFAULT_SYMBOLS.put(L, "L");
        DEFAULT_SYMBOLS.put(ST, "ST");
        DEFAULT_SYMBOLS.put(SERIALNUMBER, "SERIALNUMBER");
        DEFAULT_SYMBOLS.put(EmailAddress, "E");
        DEFAULT_SYMBOLS.put(DC, "DC");
        DEFAULT_SYMBOLS.put(UID, "UID");
        DEFAULT_SYMBOLS.put(STREET, "STREET");
        DEFAULT_SYMBOLS.put(SURNAME, "SURNAME");
        DEFAULT_SYMBOLS.put(GIVENNAME, "GIVENNAME");
        DEFAULT_SYMBOLS.put(INITIALS, "INITIALS");
        DEFAULT_SYMBOLS.put(GENERATION, "GENERATION");
        DEFAULT_SYMBOLS.put(UnstructuredAddress, "unstructuredAddress");
        DEFAULT_SYMBOLS.put(UnstructuredName, "unstructuredName");
        DEFAULT_SYMBOLS.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
        DEFAULT_SYMBOLS.put(DN_QUALIFIER, "DN");
        DEFAULT_SYMBOLS.put(PSEUDONYM, "Pseudonym");
        DEFAULT_SYMBOLS.put(POSTAL_ADDRESS, "PostalAddress");
        DEFAULT_SYMBOLS.put(NAME_AT_BIRTH, "NameAtBirth");
        DEFAULT_SYMBOLS.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
        DEFAULT_SYMBOLS.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
        DEFAULT_SYMBOLS.put(GENDER, "Gender");
        DEFAULT_SYMBOLS.put(PLACE_OF_BIRTH, "PlaceOfBirth");
        DEFAULT_SYMBOLS.put(DATE_OF_BIRTH, "DateOfBirth");
        DEFAULT_SYMBOLS.put(POSTAL_CODE, "PostalCode");
        DEFAULT_SYMBOLS.put(BUSINESS_CATEGORY, "BusinessCategory");
        DEFAULT_SYMBOLS.put(TELEPHONE_NUMBER, "TelephoneNumber");
        DEFAULT_SYMBOLS.put(NAME, "Name");
        DEFAULT_SYMBOLS.put(ORGANIZATION_IDENTIFIER, "organizationIdentifier");

        DEFAULT_LOOKUP.put("c", C);
        DEFAULT_LOOKUP.put("o", O);
        DEFAULT_LOOKUP.put("t", T);
        DEFAULT_LOOKUP.put("ou", OU);
        DEFAULT_LOOKUP.put("cn", CN);
        DEFAULT_LOOKUP.put("l", L);
        DEFAULT_LOOKUP.put("st", ST);
        DEFAULT_LOOKUP.put("sn", SURNAME);
        DEFAULT_LOOKUP.put("serialnumber", SERIALNUMBER);
        DEFAULT_LOOKUP.put("street", STREET);
        DEFAULT_LOOKUP.put("emailaddress", E);
        DEFAULT_LOOKUP.put("dc", DC);
        DEFAULT_LOOKUP.put("e", E);
        DEFAULT_LOOKUP.put("uid", UID);
        DEFAULT_LOOKUP.put("surname", SURNAME);
        DEFAULT_LOOKUP.put("givenname", GIVENNAME);
        DEFAULT_LOOKUP.put("initials", INITIALS);
        DEFAULT_LOOKUP.put("generation", GENERATION);
        DEFAULT_LOOKUP.put("description", DESCRIPTION);
        DEFAULT_LOOKUP.put("role", ROLE);
        DEFAULT_LOOKUP.put("unstructuredaddress", UnstructuredAddress);
        DEFAULT_LOOKUP.put("unstructuredname", UnstructuredName);
        DEFAULT_LOOKUP.put("uniqueidentifier", UNIQUE_IDENTIFIER);
        DEFAULT_LOOKUP.put("dn", DN_QUALIFIER);
        DEFAULT_LOOKUP.put("dnq", DN_QUALIFIER);
        DEFAULT_LOOKUP.put("pseudonym", PSEUDONYM);
        DEFAULT_LOOKUP.put("postaladdress", POSTAL_ADDRESS);
        DEFAULT_LOOKUP.put("nameatbirth", NAME_AT_BIRTH);
        DEFAULT_LOOKUP.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
        DEFAULT_LOOKUP.put("countryofresidence", COUNTRY_OF_RESIDENCE);
        DEFAULT_LOOKUP.put("gender", GENDER);
        DEFAULT_LOOKUP.put("placeofbirth", PLACE_OF_BIRTH);
        DEFAULT_LOOKUP.put("dateofbirth", DATE_OF_BIRTH);
        DEFAULT_LOOKUP.put("postalcode", POSTAL_CODE);
        DEFAULT_LOOKUP.put("businesscategory", BUSINESS_CATEGORY);
        DEFAULT_LOOKUP.put("telephonenumber", TELEPHONE_NUMBER);
        DEFAULT_LOOKUP.put("name", NAME);
        DEFAULT_LOOKUP.put("org_id", ORGANIZATION_IDENTIFIER);
        DEFAULT_LOOKUP.put("organizationidentifier", ORGANIZATION_IDENTIFIER);
    }

    private KseX500NameStyle() {
    }

    @Override
    public ASN1ObjectIdentifier attrNameToOID(String attrName) {
        return IETFUtils.decodeAttrName(attrName, DEFAULT_LOOKUP);
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

                    IETFUtils.appendTypeAndValue(buf, atv[j], DEFAULT_SYMBOLS);
                }
            } else {
                IETFUtils.appendTypeAndValue(buf, rdns[i].getFirst(), DEFAULT_SYMBOLS);
            }
        }

        return buf.toString();
    }
}
