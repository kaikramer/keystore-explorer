/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

import java.util.List;

/**
 * Singleton buffer for copy/paste. Holds at most one KeyStore entry.
 */
public class Buffer {
    private static List<BufferEntry> bufferEntries;

    private Buffer() {
    }

    /**
     * Populate buffer with supplied entry.
     *
     * @param bufferEntries Buffer entry
     */
    public static void populate(List<BufferEntry> bufferEntries) {
        Buffer.bufferEntries = bufferEntries;
    }

    /**
     * Interrogate buffer.
     *
     * @return Buffer entry or null if empty
     */
    public static List<BufferEntry> interrogate() {
        return bufferEntries;
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
        if (bufferEntries != null) {
            for (BufferEntry bufferEntry : bufferEntries) {
                bufferEntry.clear();
            }
        }

        bufferEntries = null;
    }
}
