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
package org.kse.utilities.pem;

/**
 * PEM header attribute.
 *
 */
public class PemAttribute {
	private String name;
	private String value;

	/**
	 * Construct PEM header attribute.
	 *
	 * @param name
	 *            Name
	 * @param value
	 *            Value
	 */
	public PemAttribute(String name, String value) {
		this.name = name;
		this.value = value;
	}

	/**
	 * Get attribute name.
	 *
	 * @return Name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get attribute value.
	 *
	 * @return Value
	 */
	public String getValue() {
		return value;
	}

	/**
	 * Get string representation of attribute suitable for inclusion in encoded
	 * PEM: "<name>: <value>".
	 *
	 * @return String representation
	 */
	@Override
	public String toString() {
		return name + ": " + value;
	}
}
