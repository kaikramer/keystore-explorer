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

import org.kse.gui.util.ResourceBundleCache;

/**
 * Options for PKCS#12 encryption (currently only strong/legacy)
 */
public enum Pkcs12EncryptionSetting {
    strong("Pkcs12EncryptionSetting.strong"),
    legacy("Pkcs12EncryptionSetting.legacy");

    private String resourceBundleKey;

    Pkcs12EncryptionSetting(String resourceBundleKey) {
        this.resourceBundleKey = resourceBundleKey;
    }

    @Override
    public String toString() {
        // This enumeration is referenced by KsePreferences so its static fields
        // are initialized before the language setting is populated. Use the
        // ResourceBundleCache singleton for accessing the resource bundle.
        return ResourceBundleCache.INSTANCE.getString("org/kse/gui/preferences/resources", resourceBundleKey);
    }
}
