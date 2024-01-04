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
package org.kse.utilities;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class StringUtils {

    private StringUtils() {
    }

    /**
     * Trims passed string and converts it to null if the resulting string has length zero.
     *
     * @param str String to process
     * @return Trimmed string or null
     */
    public static String trimAndConvertEmptyToNull(String str) {

        if (str == null) {
            return null;
        }

        String newStr = str.trim();

        if (newStr.isEmpty()) {
            return null;
        }

        return newStr;
    }

    /**
     * Checks if a String is null, empty or whitespace-only.
     *
     * @param str the String to check
     * @return true if the String is null, empty or whitespace-only
     */
    public static boolean isBlank(String str) {

        return trimAndConvertEmptyToNull(str) == null;

    }

    /**
     * Add given string to list. The string is put at the first position of the new list. If the list already
     * contains this value, it is moved to the first position instead. If maxSize is exceeded after adding the value,
     * the last item in the list is removed.
     * <p>
     *     Note: This does not modify the input list (as it is probably immutable), but returns a new list instead.
     * </p>
     *
     * @param value   The new item to be added.
     * @param list    Current list of strings.
     * @param maxSize Maximum number of items to keep in list.
     * @return New list of strings with new item at the first position.
     */
    public static List<String> addToList(String value, List<String> list, int maxSize) {
        LinkedList<String> newList = new LinkedList<>(list);

        if (newList.contains(value)) {
            newList.remove(value);
            newList.addFirst(value);
            return newList;
        }

        newList.addFirst(value);

        if (newList.size() > maxSize) {
            newList.removeLast();
        }
        return newList;
    }

    /**
     * Returns a localized short/medium date time string.
     *
     * @param date The date to convert into a string
     * @return localized short/medium date time string
     */
    public static String formatDate(Date date) {
        DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM);

        if (dateFormat instanceof SimpleDateFormat) {
            SimpleDateFormat sdf = (SimpleDateFormat) dateFormat;
            // we want short date format but with 4 digit year
            sdf.applyPattern(sdf.toPattern().replaceAll("y+", "yyyy").concat(" z"));
        }

        return dateFormat.format(date);
    }
}
