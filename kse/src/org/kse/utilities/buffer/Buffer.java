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
package org.kse.utilities.buffer;

/**
 * Singleton buffer for copy/paste. Holds at most one KeyStore entry.
 *
 */
public class Buffer {
	private static BufferEntry bufferEntry;

	private Buffer() {
	}

	/**
	 * Populate buffer with supplied entry.
	 *
	 * @param bufferEntry
	 *            Buffer entry
	 */
	public static void populate(BufferEntry bufferEntry) {
		Buffer.bufferEntry = bufferEntry;
	}

	/**
	 * Interrogate buffer.
	 *
	 * @return Buffer entry or null if empty
	 */
	public static BufferEntry interrogate() {
		return bufferEntry;
	}

	/**
	 * Is buffer clear?
	 *
	 * @return True if its is
	 */
	public static boolean isClear() {
		return (interrogate() == null);
	}

	/**
	 * Is buffer populated?
	 *
	 * @return True if its is
	 */
	public static boolean isPopulated() {
		return (interrogate() != null);
	}

	/**
	 * Clear buffer.
	 */
	public static void clear() {
		if (bufferEntry != null) {
			bufferEntry.clear();
		}

		bufferEntry = null;
	}
}
