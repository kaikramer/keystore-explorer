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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;

/**
 * Class of utility methods to copy data between I/O streams.
 *
 */
public class CopyUtil {
	private CopyUtil() {
	}

	/**
	 * Copy data from one stream to another and do not close I/O.
	 *
	 * @param in
	 *            Input stream
	 * @param out
	 *            Output stream
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public static void copy(InputStream in, OutputStream out) throws IOException {
		byte[] buffer = new byte[2048];
		int i;
		while ((i = in.read(buffer)) > 0) {
			out.write(buffer, 0, i);
		}
	}

	/**
	 * Copy data from one stream to another and close I/O.
	 *
	 * @param in
	 *            Input stream
	 * @param out
	 *            Output stream
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public static void copyClose(InputStream in, OutputStream out) throws IOException {
		try {
			copy(in, out);
		} finally {
			IOUtils.closeQuietly(in);
			IOUtils.closeQuietly(out);
		}
	}

	/**
	 * Copy data from a reader to a writer and do not close I/O.
	 *
	 * @param reader
	 *            Reader
	 * @param writer
	 *            Writer
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public static void copy(Reader reader, Writer writer) throws IOException {
		char[] buffer = new char[2048];
		int i;
		while ((i = reader.read(buffer)) > 0) {
			writer.write(buffer, 0, i);
		}
	}

	/**
	 * Copy data from a reader to a writer and close I/O.
	 *
	 * @param reader
	 *            Reader
	 * @param writer
	 *            Writer
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public static void copyClose(Reader reader, Writer writer) throws IOException {
		try {
			copy(reader, writer);
		} finally {
			IOUtils.closeQuietly(reader);
			IOUtils.closeQuietly(writer);
		}
	}
}
