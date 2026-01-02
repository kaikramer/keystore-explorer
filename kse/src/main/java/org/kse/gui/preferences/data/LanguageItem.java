/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

package org.kse.gui.preferences.data;

/**
 * Language class for supporting language text.
 */
public class LanguageItem {
    public static final String SYSTEM_LANGUAGE = "system";

    private String displayName;
    private String isoCode;

    public LanguageItem(String displayName, String isoCode) {
        super();
        this.displayName = displayName;
        this.isoCode = isoCode;
    }

    public String getIsoCode() {
        return isoCode;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
