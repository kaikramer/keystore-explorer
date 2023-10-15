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
package org.kse.utilities.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.encoders.Hex;

/**
 * Class of utility methods to output data in hex.
 *
 * TODO cleanup; centralize all hex conversions in KSE
 */
public class HexUtil {
    private static final String NEWLINE = "\n";

    private HexUtil() {
    }

    /**
     * Get hex string for the supplied big integer: "0x<hex string>" where hex
     * string is output in groups of exactly four characters subdivided by
     * spaces.
     *
     * @param bigInt Big integer
     * @return Hex string
     */
    public static String getHexString(BigInteger bigInt) {
        return getHexString(bigInt, "0x", 4, 0);
    }

    /**
     * Get hex string for the supplied big integer: "<prefix><hex string>" where hex
     * string is optionally output in groups of n characters subdivided by
     * spaces.
     *
     * @param bigInt Big integer
     * @param groupSize Size of char groups separated by spaces (use 0 to disable), 0-padding is added if necessary
     * @param prefix Prefix to put before actual hex data
     * @param maxLineLength Add new line when max line length is reached; "0" means no line breaks
     * @return Hex string
     */
    public static String getHexString(BigInteger bigInt, String prefix, int groupSize, int maxLineLength) {
        // Convert number to hex string
        return getHexString(bigInt.toByteArray(), prefix, groupSize, maxLineLength);
    }

    /**
     * Get hex string for the supplied byte array: "0x<hex string>" where hex
     * string is output in groups of exactly four characters subdivided by
     * spaces.
     *
     * @param bytes Byte array
     * @return Hex string
     */
    public static String getHexString(byte[] bytes) {
        return getHexString(bytes, "0x", 4, 0);
    }

    /**
     * Get hex string for the supplied big integer: "<prefix><hex string>" where hex
     * string is optionally output in groups of n characters subdivided by
     * spaces.
     *
     * @param bytes A byte array
     * @param groupSize Size of char groups separated by spaces (use 0 to disable), 0-padding is added if necessary
     * @param prefix Prefix to put before actual hex data
     * @param maxLineLength Add new line when max line length is reached; "0" means no line breaks
     * @return Hex string
     */
    public static String getHexString(byte[] bytes, String prefix, int groupSize, int maxLineLength) {
        String hex = Hex.toHexString(bytes).toUpperCase();

        // Get number padding bytes
        int padding = (4 - (hex.length() % 4));

        // Insert any required padding to get groups of exactly "groupSize" characters
        if ((padding > 0) && (padding < groupSize)) {
            StringBuilder sb = new StringBuilder(hex);

            for (int i = 0; i < padding; i++) {
                sb.insert(0, '0');
            }

            hex = sb.toString();
        }

        // Output with leading prefix (usually "0x"), spaces to form groups and line breaks
        StringBuilder sb = new StringBuilder();

        sb.append(prefix);

        for (int i = 0; i < hex.length(); i++) {
            sb.append(hex.charAt(i));

            if (groupSize != 0 && (((i + 1) % 4) == 0) && ((i + 1) != hex.length())) {
                sb.append(' ');
            }

            if (maxLineLength != 0 && (i + 1) % maxLineLength == 0) {
                sb.append('\n');
            }
        }

        return sb.toString();
    }

    /**
     * Get bytes as a formatted String. Returned in base-16
     * with given separator every two characters padded with a leading 0 if
     * necessary to make for an even number of hex characters.
     *
     * @param data      The bytes
     * @param separator Separator character
     * @return The message digest
     */
    public static String getHexStringWithSep(byte[] data, char separator) {

        StringBuilder strBuff = new StringBuilder(Hex.toHexString(data).toUpperCase());

        if ((strBuff.length() % 2) == 1) {
            strBuff.insert(0, '0');
        }

        if (strBuff.length() > 2) {
            for (int i = 2; i < strBuff.length(); i += 3) {
                strBuff.insert(i, separator);
            }
        }

        return strBuff.toString();
    }

    /**
     * Get hex and clear text dump of byte array.
     *
     * @param bytes Array of bytes
     * @return Hex/clear dump
     * @throws IOException If an I/O problem occurs
     */
    public static String getHexClearDump(byte[] bytes) throws IOException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes)) {
            // Divide dump into 16 bytes lines
            StringBuilder sb = new StringBuilder();

            byte[] line = new byte[16];
            int read = -1;
            boolean firstLine = true;

            while ((read = bais.read(line)) != -1) {
                if (firstLine) {
                    firstLine = false;
                } else {
                    sb.append(NEWLINE);
                }

                sb.append(getHexClearLineDump(line, read));
            }

            return sb.toString();
        }
    }

    private static String getHexClearLineDump(byte[] bytes, int len) {
        StringBuilder sbHex = new StringBuilder();
        StringBuilder sbClr = new StringBuilder();

        for (int cnt = 0; cnt < len; cnt++) {
            // Convert byte to int
            byte b = bytes[cnt];
            int i = b & 0xFF;

            // First part of byte will be one hex char
            int i1 = (int) Math.floor(i / 16d);

            // Second part of byte will be one hex char
            int i2 = i % 16;

            // Get hex characters
            sbHex.append(Character.toUpperCase(Character.forDigit(i1, 16)));
            sbHex.append(Character.toUpperCase(Character.forDigit(i2, 16)));

            if ((cnt + 1) < len) {
                // Divider between hex characters
                sbHex.append(' ');
                if (((cnt + 1) % 8) == 0) {
                    // Divider between 8 hex characters
                    sbHex.append(' ');
                }
            }

            // Get clear character

            // Character to display if character not defined in Unicode or is a
            // control character
            char c = '.';

            // Not a control character and defined in Unicode
            if ((!Character.isISOControl((char) i)) && (Character.isDefined((char) i))) {
                c = (char) i;
            }

            sbClr.append(c);
        }

        /*
         * Put both dumps together in one string (hex, clear) with appropriate
         * padding between them (pad to array length)
         */
        StringBuilder strBuff = new StringBuilder();

        strBuff.append(sbHex);

        int i = bytes.length - len;
        for (int cnt = 0; cnt < i; cnt++) {
            strBuff.append("   "); // Each missing byte takes up three spaces
            if (((cnt + 1) % 8) == 0) {
                // Add a space for each 8 hex characters
                strBuff.append(' ');
            }
        }

        strBuff.append("   "); // The gap between hex and clear output is three
        // spaces
        strBuff.append(sbClr);

        return strBuff.toString();
    }
}
