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
package org.kse.crypto.keystore;

/**
 * Enumeration of MS CAPI Certificate Store Types supported by the KeyStoreUtil
 * class.
 */
public enum MsCapiStoreType {
    PERSONAL("Windows-MY"),
    ROOT("Windows-ROOT");

    private String jce;

    MsCapiStoreType(String jce) {
        this.jce = jce;
    }

    /**
     * Get MsCapiStoreType type JCE name.
     *
     * @return JCE name
     */
    public String jce() {
        return jce;
    }
}
