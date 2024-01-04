/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
package org.kse.utilities.io;

import java.nio.ByteBuffer;

/**
 * Class of utility methods to get and put values as unsigned to a ByteBuffer
 * object. As Java has no concept of unsigned values the next biggest type is
 * used when getting or putting values to the ByteBuffer, e.g. when putting a
 * byte we supply a short, when we get an integer we actually get a long.
 */
public class UnsignedUtil {
    private UnsignedUtil() {
    }

    /**
     * Get an unsigned byte from the byte buffer.
     *
     * @param bb Byte buffer
     * @return Unsigned byte stored in a short to retain sign
     */
    public static short getByte(ByteBuffer bb) {
        return ((short) (bb.get() & 0xff));
    }

    /**
     * Put a byte into the byte buffer unsigned.
     *
     * @param bb    Byte buffer
     * @param value Byte to store, supplied as a short to retain sign
     */
    public static void putByte(ByteBuffer bb, short value) {
        bb.put((byte) (value & 0xff));
    }

    /**
     * Get an unsigned short from the byte buffer.
     *
     * @param bb Byte buffer
     * @return Unsigned short stored in an int to retain sign
     */
    public static int getShort(ByteBuffer bb) {
        return (bb.getShort() & 0xffff);
    }

    /**
     * Put a short into the byte buffer unsigned.
     *
     * @param bb    Byte buffer
     * @param value Short to store, supplied as an int to retain sign
     */
    public static void putShort(ByteBuffer bb, int value) {
        bb.putShort((short) (value & 0xffff));
    }

    /**
     * Get an unsigned int from the byte buffer.
     *
     * @param bb Byte buffer
     * @return Unsigned int stored in a long to retain sign
     */
    public static long getInt(ByteBuffer bb) {
        return (bb.getInt() & 0xffffffffL);
    }

    /**
     * Put an int into the byte buffer unsigned.
     *
     * @param bb    Byte buffer
     * @param value Int to store, supplied as a long to retain sign
     */
    public static void putInt(ByteBuffer bb, long value) {
        bb.putInt((int) (value & 0xffffffffL));
    }
}
