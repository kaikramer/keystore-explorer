/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
 */
public class HexUtil {
	private static final String NEWLINE = "\n";

	private HexUtil() {
	}

	/**
	 * Get hex string for the supplied big integer: "0x<hex string>" where hex
	 * string is output in groups of exactly four characters sub-divided by
	 * spaces.
	 *
	 * @param bigInt
	 *            Big integer
	 * @return Hex string
	 */
	public static String getHexString(BigInteger bigInt) {
		// Convert number to hex string
		String hex = bigInt.toString(16).toUpperCase();

		// Get number padding bytes
		int padding = (4 - (hex.length() % 4));

		// Insert any required padding to get groups of exactly 4 characters
		if ((padding > 0) && (padding < 4)) {
			StringBuilder sb = new StringBuilder(hex);

			for (int i = 0; i < padding; i++) {
				sb.insert(0, '0');
			}

			hex = sb.toString();
		}

		// Output with leading "0x" and spaces to form groups
		StringBuilder strBuff = new StringBuilder();

		strBuff.append("0x");

		for (int i = 0; i < hex.length(); i++) {
			strBuff.append(hex.charAt(i));

			if ((((i + 1) % 4) == 0) && ((i + 1) != hex.length())) {
				strBuff.append(' ');
			}
		}

		return strBuff.toString();
	}

	/**
	 * Get bytes as a formatted String. Returned in base-16
	 * with given separator every two characters padded with a leading 0 if
	 * necessary to make for an even number of hex characters.
	 *
	 * @param data
	 *            The bytes
	 * @param separator
	 *            Separator character
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
	 * Get hex string for the supplied byte array: "0x<hex string>" where hex
	 * string is output in groups of exactly four characters sub-divided by
	 * spaces.
	 *
	 * @param bytes
	 *            Byte array
	 * @return Hex string
	 */
	public static String getHexString(byte[] bytes) {
		return getHexString(new BigInteger(1, bytes));
	}

	/**
	 * Get hex and clear text dump of byte array.
	 *
	 * @param bytes
	 *            Array of bytes
	 * @return Hex/clear dump
	 * @throws IOException
	 *             If an I/O problem occurs
	 */
	public static String getHexClearDump(byte[] bytes) throws IOException {
		try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes)) {
			// Divide dump into 8 byte lines
			StringBuilder sb = new StringBuilder();


			byte[] line = new byte[8];
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
			}

			// Get clear character

			// Character to display if character not defined in Unicode or is a
			// control charcter
			char c = '.';

			// Not a control character and defined in Unicode
			if ((!Character.isISOControl((char) i)) && (Character.isDefined((char) i))) {
				Character clr = Character.valueOf((char) i);
				c = clr.charValue();
			}

			sbClr.append(c);
		}

		/*
		 * Put both dumps together in one string (hex, clear) with appropriate
		 * padding between them (pad to array length)
		 */
		StringBuilder strBuff = new StringBuilder();

		strBuff.append(sbHex.toString());

		int i = bytes.length - len;
		for (int cnt = 0; cnt < i; cnt++) {
			strBuff.append("   "); // Each missing byte takes up three spaces
		}

		strBuff.append("   "); // The gap between hex and clear output is three
		// spaces
		strBuff.append(sbClr.toString());

		return strBuff.toString();
	}
}
