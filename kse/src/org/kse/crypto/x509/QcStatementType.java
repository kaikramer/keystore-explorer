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

/**
 *
 * Qualified Certificate Statements (1.3.6.1.5.5.7.1.3).
 *
 */
public enum QcStatementType {

	// @formatter:off

	QC_SYNTAX_V1("1.3.6.1.5.5.7.11.1", "QCSyntaxV1"),
	QC_SYNTAX_V2("1.3.6.1.5.5.7.11.2", "QCSyntaxV2"),
	QC_COMPLIANCE("0.4.0.1862.1.1", "QCCompliance"),
	QC_EU_LIMIT_VALUE("0.4.0.1862.1.2", "QCEuLimitValue"),
	QC_RETENTION_PERIOD("0.4.0.1862.1.3", "QCRetentionPeriod"),
	QC_SSCD("0.4.0.1862.1.4", "QCSSCD"),
	QC_PDS("0.4.0.1862.1.5", "QCPDS"),
	QC_TYPE("0.4.0.1862.1.6", "QCType"),
	UNKNOWN("0", "unknown");

	// @formatter:on

	private String oid;
	private String friendlyKey;

	QcStatementType(String oid, String friendlyKey) {
		this.oid = oid;
		this.friendlyKey = friendlyKey;
	}

	/**
	 * Resolve the supplied object identifier to a matching type.
	 *
	 * @param oid
	 *            Object identifier
	 * @return Type or null if none
	 */
	public static QcStatementType resolveOid(String oid) {
		for (QcStatementType type : values()) {
			if (oid.equals(type.oid())) {
				return type;
			}
		}

		return UNKNOWN;
	}

	/**
	 * Get Access Method's Object Identifier.
	 *
	 * @return Object Identifier
	 */
	public String oid() {
		return oid;
	}

	/**
	 * Get friendly key for resource string
	 *
	 * @return Key for resource string
	 */
	public String getResKey() {
		return friendlyKey;
	}
}
