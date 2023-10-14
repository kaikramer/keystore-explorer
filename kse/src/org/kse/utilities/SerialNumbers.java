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

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

public class SerialNumbers {

    static final SecureRandom rng = new SecureRandom();

    private SerialNumbers() {
    }

    /**
     * Returns a new serial number from current time and random bytes.
     *
     * @param length the total length of the resulting serial number (bytes from current time and rest filled
     *                    with random data); minimum is 8, maximum is 20
     * @return new serial number as decimal format string
     */
    public static BigInteger generate(int length) {
        if (length < 8 || length > 20) {
            throw new IllegalArgumentException("Length parameter must be between 8 and 20");
        }

        byte[] timeBytes = BigInteger.valueOf(System.currentTimeMillis() / 1000).toByteArray();
        byte[] rndBytes = new byte[length - timeBytes.length];
        rng.nextBytes(rndBytes);
        byte[] snBytes = Arrays.concatenate(rndBytes, timeBytes);

        // ensure most significant byte is positive
        snBytes[0] &= 0x7F;

        return new BigInteger(1, snBytes);
    }
}
