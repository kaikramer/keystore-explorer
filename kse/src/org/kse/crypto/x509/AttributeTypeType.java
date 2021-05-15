/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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

import java.util.ResourceBundle;

/**
 *
 * Enumeration of Attribute Types.
 *
 */
public enum AttributeTypeType {

	// @formatter:off

	COMMON_NAME("2.5.4.3", "CommonNameAttributeType"),
	SERIAL_NUMBER("2.5.4.5", "SerialNumberAttributeType"),
	COUNTRY_NAME("2.5.4.6", "CountryNameAttributeType"),
	LOCALITY_NAME("2.5.4.7", "LocalityNameAttributeType"),
	STATE_NAME("2.5.4.8", "StateOrProvinceNameAttributeType"),
	STREET_ADDRESS("2.5.4.9", "StreetAddressAttributeType"),
	ORGANIZATION_NAME("2.5.4.10", "OrganizationNameAttributeType"),
	ORGANIZATIONAL_UNIT("2.5.4.11", "OrganizationalUnitNameAttributeType"),
	TITLE("2.5.4.12", "TitleAttributeType"),
	EMAIL_ADDRESS("1.2.840.113549.1.9.1", "EmailAddressAttributeType"),
	UNSTRUCTURED_NAME("1.2.840.113549.1.9.2", "UnstructuredNameAttributeType"),
	UNSTRUCTURED_ADDRESS("1.2.840.113549.1.9.8", "UnstructuredAddressAttributeType"),
	USER_ID("0.9.2342.19200300.100.1.1", "UserIdAttributeType"),
	MAIL("0.9.2342.19200300.100.1.3", "MailAttributeType"),
	DOMAIN_COMPONENT("0.9.2342.19200300.100.1.2.25", "DomainComponentAttributeType"),

	DATE_OF_BIRTH("1.3.6.1.5.5.7.9.1", "DateOfBirth"),
	PLACE_OF_BIRTH("1.3.6.1.5.5.7.9.2", "PlaceOfBirth"),
	GENDER("1.3.6.1.5.5.7.9.3", "Gender"),
	COUNTRY_OF_CITIZENSHIP("1.3.6.1.5.5.7.9.4", "CountryOfCitizenship"),
	COUNTRY_OF_RESIDENCE("1.3.6.1.5.5.7.9.5", "CountryOfResidence"),

	UNKNOWN("0", "unknown");

	// @formatter:on

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
	private String oid;
	private String friendlyKey;

	AttributeTypeType(String oid, String friendlyKey) {
		this.oid = oid;
		this.friendlyKey = friendlyKey;
	}

	/**
	 * Get type's friendly name.
	 *
	 * @return Friendly name
	 */
	public String friendly() {
		return res.getString(friendlyKey);
	}

	/**
	 * Resolve the supplied object identifier to a matching type.
	 *
	 * @param oid
	 *            Object identifier
	 * @return Type or null if none
	 */
	public static AttributeTypeType resolveOid(String oid) {
		for (AttributeTypeType extType : values()) {
			if (oid.equals(extType.oid())) {
				return extType;
			}
		}

		return UNKNOWN;
	}

	/**
	 * Get Attribute Type's Object Identifier.
	 *
	 * @return Object Identifier
	 */
	public String oid() {
		return oid;
	}
}
