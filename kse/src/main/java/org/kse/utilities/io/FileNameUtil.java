/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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

/**
 * Class for manipulating and checking file names.
 */
public class FileNameUtil {

    private FileNameUtil() {
    }

    /**
     * Make a string safely usable as a file name by removing all illegal characters (and a few
     * more).
     *
     * @param s A string that is supposed to be used as a file name and therefore cleaned from
     *          illegal characters.
     * @return Sanitized string
     */
    public static String cleanFileName(String s) {
        return s.replaceAll("[^a-zA-Z0-9\\._]+", "_");
    }

    /**
     * Remove file extension
     *
     * @param fileName file name (with or without path)
     * @return File name without extension
     */
    public static String removeExtension(String fileName) {

        if (fileName == null) {
            return null;
        }

        // find position in string where extension begins (and handle paths like "C:\my.dir\fileName")
        int extensionPos = fileName.lastIndexOf('.');
        int lastSeparator = Math.max(fileName.lastIndexOf('/'), fileName.lastIndexOf('\\'));
        int index = (lastSeparator > extensionPos) ? -1 : extensionPos;

        // no extension found
        if (index == -1) {
            return fileName;
        }

        return fileName.substring(0, index);
    }
}
