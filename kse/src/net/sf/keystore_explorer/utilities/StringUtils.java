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

		return trimAndConvertEmptyToNull(str) == null;

	}

	/**
	 * Add a new item to a semicolon separated list of strings.
	 *
	 * @param newItem
	 *          The new item to be added.
	 * @param semicolonSepList
	 *          Current semicolon separated list of strings.
	 * @param maxItems
	 *          Maximum number of items to keep in list.
	 * @return New semicolon separated list of strings with new item at the first position.
	 */
	public static String addToList(String newItem, String semicolonSepList, int maxItems) {

		// add new item at first position of the list
		StringBuilder sb = new StringBuilder(newItem);
		String[] items = semicolonSepList.split(";");
		for (int i = 0; i < items.length && i < maxItems; i++) {

			String port = items[i];

			// if saved list already contains new item, bring it to first position
			if (port.equals(newItem)) {
				continue;
			}

			sb.append(";");
			sb.append(port);
		}

		return sb.toString();
	}
}
