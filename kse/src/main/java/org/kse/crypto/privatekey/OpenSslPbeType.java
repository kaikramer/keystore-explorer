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
package org.kse.crypto.privatekey;

import java.util.ResourceBundle;

/**
 * Enumeration of Password based Encryption (PBE) Types supported by
 * OpenSslPvkUtil.
 */
public enum OpenSslPbeType implements PbeType {
    /**
     * DES CBC
     */
    DES_CBC("DES-CBC", "DES/CBC/PKCS5Padding", 64, 64, "OpenSslPbeType.PbeWithDesCbc"),

    /**
     * Triple DES CBC
     */
    DESEDE_CBC("DES-EDE3-CBC", "DESede/CBC/PKCS5Padding", 192, 64, "OpenSslPbeType.PbeWithDesedeCbc"),

    /**
     * 128 bit AES CBC
     */
    AES_128BIT_CBC("AES-128-CBC", "AES/CBC/PKCS5Padding", 128, 128, "OpenSslPbeType.PbeWith128BitAesCbc"),

    /**
     * 192 bit AES CBC
     */
    AES_192BIT_CBC("AES-192-CBC", "AES/CBC/PKCS5Padding", 192, 128, "OpenSslPbeType.PbeWith192BitAesCbc"),

    /**
     * 256 bit AES CBC
     */
    AES_256BIT_CBC("AES-256-CBC", "AES/CBC/PKCS5Padding", 256, 128, "OpenSslPbeType.PbeWith1256itAesCbc");

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/privatekey/resources");
    private String dekInfo;
    private String jceCipher;
    private int keySize;
    private int saltSize;
    private String friendlyKey;

    OpenSslPbeType(String dekInfo, String jceCipher, int keySize, int saltSize, String friendlyKey) {
        this.dekInfo = dekInfo;
        this.jceCipher = jceCipher;
        this.keySize = keySize;
        this.saltSize = saltSize;
        this.friendlyKey = friendlyKey;
    }

    /**
     * PBE type DEK-Info name.
     *
     * @return DEK-Info name
     */
    public String dekInfo() {
        return dekInfo;
    }

    /**
     * Get JCE cipher transformation.
     *
     * @return JCE cipher trandformation
     */
    public String jceCipher() {
        return jceCipher;
    }

    /**
     * Get cipher key size in bits.
     *
     * @return Key size
     */
    public int keySize() {
        return keySize;
    }

    /**
     * Get cipher salt size in bits.
     *
     * @return Salt size
     */
    public int saltSize() {
        return saltSize;
    }

    /**
     * Get type's friendly name.
     *
     * @return Friendly name
     */
    @Override
    public String friendly() {
        return res.getString(friendlyKey);
    }

    /**
     * Resolve the supplied DEK-Info name to a matching PBE type.
     *
     * @param dekInfo DEK-Info name name
     * @return PBE type or null if none
     */
    public static OpenSslPbeType resolveDekInfo(String dekInfo) {
        for (OpenSslPbeType pbeType : values()) {
            if (dekInfo.equals(pbeType.dekInfo())) {
                return pbeType;
            }
        }

        return null;
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
