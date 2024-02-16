package org.kse.crypto.x509;

import java.util.ResourceBundle;
import java.util.function.UnaryOperator;

/**
 * Format the serial number in different variants
 */
public enum SerialNumberFormatter {

	/**
	 * uppercase hex string with a leading 0x prefix
	 */
	HEX_STRING("SerialNumberFormatter.HexString", serialNumber -> "0x" + serialNumber),

	/**
	 * lowercase hex string, every byte is separated with a colon
	 */
	LOWERCASE_COLON("SerialNumberFormatter.LowercaseColon", serialNumber -> {
		String tmpSerialNumber = serialNumber.toLowerCase();
		if (tmpSerialNumber.length() % 2 != 0) {
			tmpSerialNumber = "0" + tmpSerialNumber;
		}
		char[] chars = tmpSerialNumber.toCharArray();
		StringBuilder result = new StringBuilder();
		for (int i = 0; i < chars.length; i++) {
			result.append(chars[i]);
			if (i % 2 == 1 && i < chars.length - 1) {
				result.append(':');
			}
		}
		return result.toString();
	});

	private final UnaryOperator<String> formatter;

	private final String resourceBundleKey;

	private static ResourceBundle res;

	SerialNumberFormatter(String resourceBundleKey, UnaryOperator<String> formatter) {
		this.formatter = formatter;
		this.resourceBundleKey = resourceBundleKey;
	}

	/**
	 * Allows to pass a resource bundle (which unfortunately cannot be initialized
	 * in this enum) that is then used to translate the result of the
	 * {@code toString()} method.
	 *
	 * @param resourceBundle An initialized resource bundle
	 */
	public static void setResourceBundle(ResourceBundle resourceBundle) {
		res = resourceBundle;
	}

	public String format(String serialNumber) {
		return formatter.apply(serialNumber);
	}

	@Override
	public String toString() {
		if (res == null) {
			return this.name();
		}
		return res.getString(this.resourceBundleKey);
	}
}
