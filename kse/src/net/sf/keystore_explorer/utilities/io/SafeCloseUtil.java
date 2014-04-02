/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2014 Kai Kramer
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
package net.sf.keystore_explorer.utilities.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.util.zip.ZipFile;

/**
 * Class of utility methods to safely close streams, readers, writers and
 * archives. By safe it ignores null parameters and any exceptions raised by
 * closing.
 * 
 */
public class SafeCloseUtil {
	private SafeCloseUtil() {
	}

	/**
	 * Safely close an input stream.
	 * 
	 * @param inputStream
	 *            Input stream
	 */
	public static void close(InputStream inputStream) {
		try {
			if (inputStream != null) {
				inputStream.close();
			}
		} catch (IOException ex) {
		}
	}

	/**
	 * Safely close an output stream.
	 * 
	 * @param outputStream
	 *            Output stream
	 */
	public static void close(OutputStream outputStream) {
		try {
			if (outputStream != null) {
				outputStream.close();
			}
		} catch (IOException ex) {
		}
	}

	/**
	 * Safely close a reader.
	 * 
	 * @param reader
	 *            Reader
	 */
	public static void close(Reader reader) {
		try {
			if (reader != null) {
				reader.close();
			}
		} catch (IOException ex) {
		}
	}

	/**
	 * Safely close a writer.
	 * 
	 * @param writer
	 *            Writer
	 */
	public static void close(Writer writer) {
		try {
			if (writer != null) {
				writer.close();
			}
		} catch (IOException ex) {
		}
	}

	/**
	 * Safely close a zip file.
	 * 
	 * @param zipFile
	 *            Zip file
	 */
	public static void close(ZipFile zipFile) {
		try {
			if (zipFile != null) {
				zipFile.close();
			}
		} catch (IOException ex) {
		}
	}
}
