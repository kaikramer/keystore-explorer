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
package org.kse.utilities.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Class of utility methods to read from streams.
 *
 */
public class ReadUtil {
	private ReadUtil() {
	}

	/**
	 * Read all bytes from the supplied input stream. Closes the input stream.
	 *
	 * @param is
	 *            Input stream
	 * @return All bytes
	 * @throws IOException
	 *             If an I/O problem occurs
	 */
	public static byte[] readFully(InputStream is) throws IOException {
		ByteArrayOutputStream baos = null;

		try {
			baos = new ByteArrayOutputStream();

			byte[] buffer = new byte[2048];
			int read = 0;

			while ((read = is.read(buffer)) != -1) {
				baos.write(buffer, 0, read);
			}

			return baos.toByteArray();
		} finally {
			IOUtils.closeQuietly(baos);
			IOUtils.closeQuietly(is);
		}
	}
}
