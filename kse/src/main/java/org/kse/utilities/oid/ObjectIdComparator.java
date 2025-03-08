/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

import static java.math.BigInteger.ZERO;

import java.math.BigInteger;
import java.util.Comparator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Comparator for Object Identifiers.
 */
public class ObjectIdComparator implements Comparator<ASN1ObjectIdentifier> {
    @Override
    public int compare(ASN1ObjectIdentifier oid1, ASN1ObjectIdentifier oid2) {
        String[] arcs1 = oid1.getId().split("\\.");
        String[] arcs2 = oid2.getId().split("\\.");

        // first try to find differences in the common number of arcs
        for (int i = 0; (i < arcs1.length) && (i < arcs2.length); i++) {
            BigInteger i1 = new BigInteger(arcs1[i]);
            BigInteger i2 = new BigInteger(arcs2[i]);

            int comparisonResult = i1.compareTo(i2);
            if (comparisonResult != 0) {
                return comparisonResult;
            }
        }

        if (arcs2.length > arcs1.length) {
            // check for the case where all additional arcs are 0
            for (int i = arcs1.length; i < arcs2.length; i++) {
                if (!new BigInteger(arcs2[i]).equals(ZERO)) {
                    return -1;
                }
            }
        }

        if (arcs1.length > arcs2.length) {
            // check for the case where all additional arcs are 0
            for (int i = arcs2.length; i < arcs1.length; i++) {
                if (!new BigInteger(arcs1[i]).equals(ZERO)) {
                    return 1;
                }
            }
        }

        return 0;
    }
}
