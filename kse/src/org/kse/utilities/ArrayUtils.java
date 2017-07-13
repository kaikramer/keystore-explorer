package org.kse.utilities;

public class ArrayUtils {

	/**
	 * Concatenate two byte arrays.
	 *
	 * @param a
	 * @param b
	 * @return Concatenation of a and b or empty byte array if both values are null
	 */
	public static byte[] add(byte[] a, byte[] b) {

		// graceful handling of null values
		if (a == null) {
			if (b == null ) {
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
}
