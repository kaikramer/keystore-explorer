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
package org.kse.crypto.jcepolicy;

import java.util.ResourceBundle;

/**
 * Enumeration of JCE cryptography strengths.
 */
public enum CryptoStrength {
    LIMITED("limited"),
    UNLIMITED("unlimited");

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/jcepolicy/resources");
    private final String manifestValue;

    CryptoStrength(String manifestValue) {
        this.manifestValue = manifestValue;
    }

    /**
     * Get friendly name
     *
     * @return Friendly name
     */
    public String friendly() {
        if (this == LIMITED) {
            return res.getString("CryptoStrength.Limited");
        } else {
            return res.getString("CryptoStrength.Unlimited");
        }
    }

    /**
     * Get manifest value.
     *
     * @return Manifest value
     */
    public String manifestValue() {
        return manifestValue;
    }
}
