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
package org.kse.utilities.pem;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;

import org.bouncycastle.util.encoders.Base64;

/**
 * Provides utility methods relating to PEM.
 *
 */
public class PemUtil {
	private static final int MAX_PRINTABLE_ENCODING_LINE_LENGTH = 64;

	// Begin OpenSSL EC parameters PEM (see "openssl ecparam -name prime256v1 -genkey -out key.pem"; missing "-noout")
	private static final String OPENSSL_EC_PARAMS_PEM_TYPE = "EC PARAMETERS";

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
		StringBuilder sbPem = new StringBuilder();

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

	/**
	 * Decode the PEM included in the supplied input stream.
	 *
	 * @param pemData PEM data as byte array
	 * @return PEM information or null if stream does not contain PEM
	 * @throws IOException
	 *             If an I/O problem occurs
	 */
	public static PemInfo decode(byte[] pemData) throws IOException {

		try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pemData);
				InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream);
				LineNumberReader lnr = new LineNumberReader(inputStreamReader)) {

			// we ignore EC parameter blocks for now
			String line = skipOverEcParams(lnr);
			StringBuilder sbBase64 = new StringBuilder();

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


	private static String skipOverEcParams(LineNumberReader lnr) throws IOException {

		String line = lnr.readLine();

		// skip over EC parameter block
		if (line != null && OPENSSL_EC_PARAMS_PEM_TYPE.equals(getTypeFromHeader(line.trim()))) {

			// now find end line
			while( (line = lnr.readLine()) != null ) {
				line = line.trim();
				if (OPENSSL_EC_PARAMS_PEM_TYPE.equals(getTypeFromFooter(line))) {
					line = lnr.readLine();
					break;
				}
			}
		}

		return line;
	}

	private static String getTypeFromHeader(String header) {
		String type = null;

		if (header.startsWith("-----BEGIN ") && header.endsWith("-----")) {
			type = header.substring(11, header.length() - 5);
		}

		return type;
	}

	private static String getTypeFromFooter(String footer) {
		String type = null;

		if (footer.startsWith("-----END ") && footer.endsWith("-----")) {
			type = footer.substring(9, footer.length() - 5);
		}

		return type;
	}
}
