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
package org.kse.utilities.oid;

import java.util.Comparator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Comparator for Object Identifiers.
 *
 */
public class ObjectIdComparator implements Comparator<ASN1ObjectIdentifier> {
	@Override
	public int compare(ASN1ObjectIdentifier oid1, ASN1ObjectIdentifier oid2) {
		int[] arcs1;
		int[] arcs2;

		try {
			arcs1 = ObjectIdUtil.extractArcs(oid1);
			arcs2 = ObjectIdUtil.extractArcs(oid2);
		} catch (InvalidObjectIdException ex) {
			throw new RuntimeException(ex);
		}

		for (int i = 0; ((i < arcs1.length) && (i < arcs2.length)); i++) {
			if (arcs1[i] > arcs2[i]) {
				return 1;
			} else if (arcs1[i] < arcs2[i]) {
				return -1;
			}
		}

		if (arcs2.length > arcs1.length) {
			for (int i = arcs1.length; i < arcs2.length; i++) {
				if (arcs2[i] != 0) {
					return -1;
				}
			}
		}

		if (arcs1.length > arcs2.length) {
			for (int i = arcs2.length; i < arcs1.length; i++) {
				if (arcs1[i] != 0) {
					return 1;
				}
			}
		}

		return 0;
	}
}
