package org.kse.utilities.io;

import java.io.Closeable;
import java.io.IOException;

public class IOUtils {

	/**
	 * Close without ever throwing an IOException
	 *
	 * @param closable
	 */
	public static void closeQuietly(Closeable closable) {
		if (closable != null) {
			try {
				closable.close();
			} catch (IOException e) {
				// ignore
			}
		}
	}
}
