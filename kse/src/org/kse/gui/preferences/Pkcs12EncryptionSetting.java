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

package org.kse.gui.preferences;

import java.util.ResourceBundle;

public enum Pkcs12EncryptionSetting {
    strong("Pkcs12EncryptionSetting.strong"),
    legacy("Pkcs12EncryptionSetting.legacy");

    private String resourceBundleKey;
    private static ResourceBundle res;

    Pkcs12EncryptionSetting(String resourceBundleKey) {
        this.resourceBundleKey = resourceBundleKey;
    }

    /**
     * Allows to pass a resource bundle (which unfortunately cannot be intialized in this enum)
     * that is then used to translate the result of the {@code toString()} method.
     * @param resourceBundle An initialized resource bundle
     */
    public static void setResourceBundle(ResourceBundle resourceBundle) {
        res = resourceBundle;
    }

    @Override
    public String toString() {
        if (res == null) {
            return this.name();
        }
        return res.getString(this.resourceBundleKey);
    }
}
