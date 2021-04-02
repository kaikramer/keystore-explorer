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
 * Enumeration of Access Methods (1.3.6.1.5.5.7.1.1).
 *
 */
public enum AccessMethodType {
	OCSP("1.3.6.1.5.5.7.48.1", "OcspAccessMethod"),
	CA_ISSUERS("1.3.6.1.5.5.7.48.2", "CaIssuersAccessMethod"),
	TIME_STAMPING("1.3.6.1.5.5.7.48.3", "TimeStampingAccessMethod"),
	CA_REPOSITORY("1.3.6.1.5.5.7.48.5",	"CaRepositoryAccessMethod");

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
	private String oid;
	private String friendlyKey;

	AccessMethodType(String oid, String friendlyKey) {
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
	public static AccessMethodType resolveOid(String oid) {
		for (AccessMethodType type : values()) {
			if (oid.equals(type.oid())) {
				return type;
			}
		}

		return null;
	}

	/**
	 * Get Access Method's Object Identifier.
	 *
	 * @return Object Identifier
	 */
	public String oid() {
		return oid;
	}
}
