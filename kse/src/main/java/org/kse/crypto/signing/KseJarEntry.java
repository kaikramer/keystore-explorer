/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

package org.kse.crypto.signing;

import java.util.jar.JarEntry;

/**
 * Augments JarEntry by adding the jarsigner flags to the entry.
 */
public class KseJarEntry extends JarEntry {

    public static final char FLAG_BLANK = ' ';
    public static final char FLAG_SIGNED = 's';
    public static final char FLAG_MANIFEST = 'm';
    public static final char FLAG_CERT = 'k';

    private String flags;

    /**
     * @param je    The JarEntry to adapt.
     * @param flags The verification flags for the JarEntry.
     */
    public KseJarEntry(JarEntry je, String flags) {
        super(je);
        this.flags = flags;
    }

    /**
     * @return the flags
     */
    public String getFlags() {
        return flags;
    }

}
