package net.sf.keystore_explorer.utilities;

public class StringUtils {

	/**
	 * Trims passed string and converts it to null if the resulting string has length zero.
	 * 
	 * @param str String to process
	 * @return Trimmed string or null
	 */
	public static String trimAndConvertEmptyToNull(String str) {
		
		if (str == null) {
			return null;
		}
		
		String newStr = str.trim();

		if (newStr.length() < 1) {
			return null;
		}

		return newStr;
	}
	
	/**
	 * Checks if a String is null, empty or whitespace-only.
	 * 
	 * @param str
	 *            the String to check
	 * @return true if the String is null, empty or whitespace-only
	 */
	public static boolean isBlank(String str) {
		
		if (trimAndConvertEmptyToNull(str) == null) {
			return true;
		}

		return false;
	}
}
