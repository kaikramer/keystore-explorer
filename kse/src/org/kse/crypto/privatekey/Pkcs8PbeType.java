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
package org.kse.crypto.privatekey;

import java.util.ResourceBundle;

/**
 * Enumeration of Password based Encryption (PBE) Types supported by Pkcs8Util.
 */
public enum Pkcs8PbeType implements PbeType {
    /**
     * SHA-1 with 2 key Triple DES
     */
    SHA1_2KEY_DESEDE("1.2.840.113549.1.12.1.4", "Pkcs8PbeType.PbeWithSha1And2KeyDesede"),

    /**
     * SHA-1 with 3 key Triple DES
     */
    SHA1_3KEY_DESEDE("1.2.840.113549.1.12.1.3", "Pkcs8PbeType.PbeWithSha1And3KeyDesede"),

    /**
     * SHA-1 with 40 bit RC2
     */
    SHA1_40BIT_RC2("1.2.840.113549.1.12.1.6", "Pkcs8PbeType.PbeWithSha1And40bitRc2"),

    /**
     * SHA-1 with 128 bit RC2
     */
    SHA1_128BIT_RC2("1.2.840.113549.1.12.1.5", "Pkcs8PbeType.PbeWithSha1And128BitRc2"),

    /**
     * SHA-1 with 40 bit RC4
     */
    SHA1_40BIT_RC4("1.2.840.113549.1.12.1.2", "Pkcs8PbeType.PbeWithSha1And40BitRc4"),

    /**
     * SHA-1 with 128 bit RC4
     */
    SHA1_128BIT_RC4("1.2.840.113549.1.12.1.1", "Pkcs8PbeType.PbeWithSha1And128BitRc4");

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/privatekey/resources");
    private String jce;
    private String friendlyKey;

    Pkcs8PbeType(String jce, String friendlyKey) {
        this.jce = jce;
        this.friendlyKey = friendlyKey;
    }

    /**
     * PBE type JCE name.
     *
     * @return JCE name
     */
    public String jce() {
        return jce;
    }

    /**
     * Get type's friendly name.
     *
     * @return Friendly name resource key name
     */
    @Override
    public String friendly() {
        return res.getString(friendlyKey);
    }

    /**
     * Returns friendly name.
     *
     * @return Friendly name
     */
    @Override
    public String toString() {
        return friendly();
    }
}
