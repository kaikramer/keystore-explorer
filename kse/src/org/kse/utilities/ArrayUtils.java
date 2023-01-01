/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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
package org.kse.utilities;

import java.util.Collections;

public class ArrayUtils {

    private ArrayUtils() {
    }

    /**
     * Concatenate two byte arrays.
     *
     * @param a array 1
     * @param b array 2
     * @return Concatenation of a and b or empty byte array if both values are null
     */
    public static byte[] add(byte[] a, byte[] b) {

        // graceful handling of null values
        if (a == null) {
            if (b == null) {
                return new byte[0];
            } else {
                return b;
            }
        }
        if (b == null) {
            return a;
        }

        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Null-safe access to iterable
     *
     * @param iterable Possibly null iterable
     * @return Immutable empty list if iterable is null, original iterable if it is not null
     */
    public static <T> Iterable<T> emptyIfNull(Iterable<T> iterable) {
        return iterable == null ? Collections.emptyList() : iterable;
    }
}
