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

public class SerialNumbers {
    /**
     * Returns a new serial number from current time and random bytes.
     *
     * @param randomBytes the length of random bytes
     * @return new serial number
     */
    public static String fromCurrentTime(int randomBytes) {
    	final long time = System.currentTimeMillis() / 1000;
        if (randomBytes <= 0) {
            return String.valueOf(time);
        }
        final SecureRandom rng = new SecureRandom();
        // ensure most significant byte is positive
        byte mostSigByte;
        do {
            mostSigByte = (byte) rng.nextInt();
        } while (mostSigByte <= 0);
        // generate remaining random bytes
        final byte[] otherRandomBytes = new byte[randomBytes - 1];
        rng.nextBytes(otherRandomBytes);
        // magnitude of a big integer from random bytes and current time
        final byte[] magnitude = new byte[randomBytes + 4];
        magnitude[0] = mostSigByte;
        System.arraycopy(otherRandomBytes, 0, magnitude, 1, otherRandomBytes.length);
        magnitude[randomBytes] = (byte) (time >> 24);
        magnitude[randomBytes + 1] = (byte) (time >> 16);
        magnitude[randomBytes + 2] = (byte) (time >> 8);
        magnitude[randomBytes + 3] = (byte) time;
        // convert bytes to a string using big integer
        return new BigInteger(1, magnitude).toString();
    }

    private SerialNumbers() {
    }
}
