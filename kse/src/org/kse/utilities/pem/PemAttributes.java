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

import java.util.ArrayList;

/**
 * PEM header attributes.
 *
 */
public class PemAttributes {
	private ArrayList<PemAttribute> attributes = new ArrayList<>();

	/**
	 * Add an attribute.
	 *
	 * @param attribute
	 *            Attribute
	 */
	public void add(PemAttribute attribute) {
		attributes.add(attribute);
	}

	/**
	 * Get attributes.
	 *
	 * @return Attributes in addition order
	 */
	public Iterable<PemAttribute> values() {
		return attributes;
	}

	/**
	 * Get the named attribute.
	 *
	 * @param name
	 *            Attribute name
	 * @return named attribute or null if none
	 */
	public PemAttribute get(String name) {
		for (PemAttribute attribute : attributes) {
			if (attribute.getName().equals(name)) {
				return attribute;
			}
		}

		return null;
	}

	/**
	 * How many attributes or contained in object?
	 *
	 * @return Size
	 */
	public int size() {
		return attributes.size();
	}
}
