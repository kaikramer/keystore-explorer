/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
package org.kse.utilities.pem;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;

import org.bouncycastle.util.encoders.Base64;
import org.kse.utilities.io.ReadUtil;

/**
 * Provides utility methods relating to PEM.
 *
 */
public class PemUtil {
	private static final int MAX_PRINTABLE_ENCODING_LINE_LENGTH = 64;

	private PemUtil() {
	}

	/**
	 * Encode the supplied information as PEM.
	 *
	 * @param pemInfo
	 *            PEM Information
	 * @return PEM encoding
	 */
	public static String encode(PemInfo pemInfo) {
		StringBuffer sbPem = new StringBuffer();

		// Ouput header
		sbPem.append("-----BEGIN ");
		sbPem.append(pemInfo.getType());
		sbPem.append("-----");
		sbPem.append("\n");

		// Output any header attributes
		PemAttributes attributes = pemInfo.getAttributes();

		if (attributes != null && attributes.size() > 0) {
			for (PemAttribute attribute : attributes.values()) {
				sbPem.append(attribute);
				sbPem.append('\n');
			}

			// Empty line separator between attributes and content
			sbPem.append('\n');
		}

		// Output content
		String base64 = new String(Base64.encode(pemInfo.getContent()));

		// Limit line lengths
		for (int i = 0; i < base64.length(); i += MAX_PRINTABLE_ENCODING_LINE_LENGTH) {
			int lineLength;

			if (i + MAX_PRINTABLE_ENCODING_LINE_LENGTH > base64.length()) {
				lineLength = base64.length() - i;
			} else {
				lineLength = MAX_PRINTABLE_ENCODING_LINE_LENGTH;
			}

			sbPem.append(base64.substring(i, i + lineLength));
			sbPem.append("\n");
		}

		// Output footer
		sbPem.append("-----END ");
		sbPem.append(pemInfo.getType());
		sbPem.append("-----");
		sbPem.append("\n");

		return sbPem.toString();
	}

	private static String getTypeFromHeader(String header) {
		String type = null;

		if (header.startsWith("-----BEGIN ")) {
			if (header.endsWith("-----")) {
				type = header.substring(11, header.length() - 5);
			}
		}

		return type;
	}

	private static String getTypeFromFooter(String footer) {
		String type = null;

		if (footer.startsWith("-----END ")) {
			if (footer.endsWith("-----")) {
				type = footer.substring(9, footer.length() - 5);
			}
		}

		return type;
	}

	/**
	 * Decode the PEM included in the supplied input stream.
	 *
	 * @param is
	 *            Input stream
	 * @return PEM information or null if stream does not contain PEM
	 * @throws IOException
	 *             If an I/O problem occurs
	 */
	public static PemInfo decode(InputStream is) throws IOException {
		byte[] streamContents = ReadUtil.readFully(is);

		try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(streamContents);
				InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream);
				LineNumberReader lnr = new LineNumberReader(inputStreamReader)) {

			String line = lnr.readLine();
			StringBuffer sbBase64 = new StringBuffer();

			if (line != null) {
				line = line.trim();
				String headerType = getTypeFromHeader(line);

				if (headerType != null) {
					line = lnr.readLine();

					PemAttributes attributes = null;

					// Read any header attributes
					if (line != null && line.contains(": ")) {
						line = line.trim();

						attributes = new PemAttributes();

						while (line != null) {
							line = line.trim();

							// Empty line - end of attributes
							if (line.equals("")) {
								line = lnr.readLine();
								break;
							}

							// Run out of attributes before blank line - not PEM
							if (!line.contains(": ")) {
								return null;
							}

							// Parse attribute from line
							int separator = line.indexOf(':');

							String attributeName = line.substring(0, separator);
							String attributeValue = line.substring(separator + 2);

							attributes.add(new PemAttribute(attributeName, attributeValue));

							line = lnr.readLine();
						}
					}

					// Read content
					while (line != null) {
						line = line.trim();
						String footerType = getTypeFromFooter(line);

						if (footerType == null) {
							sbBase64.append(line);
						} else {
							// Header and footer types do not match - not PEM
							if (!headerType.equals(footerType)) {
								return null;
							} else {
								// Decode base 64 content
								byte[] content = Base64.decode(sbBase64.toString());

								return new PemInfo(headerType, attributes, content);
							}
						}

						line = lnr.readLine();
					}
				}
			}
		}

		return null; // Not PEM
	}
}
