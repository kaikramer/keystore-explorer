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

package org.kse.crypto.secretkey;

public enum SecretKeyType {
    AES("AES", "AES", 128, 256, 64),
    ARC4("ARC4", "ARC4", 40, 2048, 8),
    BLOWFISH("BLOWFISH", "Blowfish", 32, 448, 64),
    CAMELLIA("CAMELLIA", "Camellia", 128, 256, 64),
    CHACHA("CHACHA", "ChaCha", 128, 256, 128),
    CAST5("CAST5", "CAST-128", 40, 128, 8),
    CAST6("CAST6", "CAST-256", 128, 256, 32),
    DES("DES", "DES", 64, 64, 1),
    DESEDE("DESede", "DESEDE", 128, 192, 64),
    GOST_28147("GOST28147", "GOST 28147-89", 256, 256, 1),
    GRAIN_V1("Grainv1", "Grain v1", 80, 80, 1),
    GRAIN_128("Grain128", "Grain-128", 128, 128, 1),
    HC_128("HC128", "HC-128", 128, 128, 1),
    HC_256("HC256", "HC-256", 256, 256, 1),
    HMAC_MD2("HMACMD2", "HMac-MD2", 128, 128, 1),
    HMAC_MD4("HMACMD4", "HMac-MD4", 128, 128, 1),
    HMAC_MD5("HMACMD5", "HMac-MD5", 128, 128, 1),
    HMAC_RIPEMD128("HMACRIPEMD128", "HMac-RipeMD128", 128, 128, 1),
    HMAC_RIPEMD160("HMACRIPEMD160", "HMac-RipeMD160", 160, 160, 1),
    HMAC_SHA1("HMACSHA1", "HMac-SHA1", 160, 160, 1),
    HMAC_SHA224("HMACSHA224", "HMac-SHA224", 224, 224, 1),
    HMAC_SHA256("HMACSHA256", "HMac-SHA256", 256, 256, 1),
    HMAC_SHA384("HMACSHA384", "HMac-SHA384", 384, 384, 1),
    HMAC_SHA512("HMACSHA512", "HMac-SHA512", 512, 512, 1),
    HMAC_TIGER("HMACTIGER", "HMac-Tiger", 192, 192, 1),
    NOEKEON("NOEKEON", "NOEKEON", 128, 128, 1),
    RC2("RC2", "RC2", 8, 128, 8),
    RC5("RC5", "RC5", 8, 2040, 8),
    RC6("RC6", "RC6", 128, 256, 64),
    RIJNDAEL("RIJNDAEL", "Rijndael", 128, 256, 32),
    SALSA_20("SALSA20", "Salsa20", 128, 256, 128),
    SERPENT("Serpent", "Serpent", 128, 256, 64),
    SEED("SEED", "SEED", 128, 128, 1),
    SKIPJACK("SKIPJACK", "Skipjack", 80, 80, 1),
    TEA("TEA", "TEA", 128, 128, 1),
    TWOFISH("Twofish", "Twofish", 128, 256, 64),
    THREEFISH_256("Threefish-256", "Threefish-256", 256, 256, 1),
    THREEFISH_512("Threefish-512", "Threefish-512", 512, 512, 1),
    THREEFISH_1024("Threefish-1024", "Threefish-1024", 1024, 1024, 1),
    XSALSA_20("XSALSA20", "XSalsa20", 128, 256, 128),
    XTEA("XTEA", "XTEA", 128, 128, 1);

    private String jce;
    private String friendly;
    private int minSize;
    private int maxSize;
    private int stepSize;

    SecretKeyType(String jce, String friendly, int minSize, int maxSize, int stepSize) {
        this.jce = jce;
        this.friendly = friendly;
        this.minSize = minSize;
        this.maxSize = maxSize;
        this.stepSize = stepSize;
    }

    /**
     * Get secret key type JCE name.
     *
     * @return JCE name
     */
    public String jce() {
        return jce;
    }

    /**
     * Get secret key type friendly name.
     *
     * @return Friendly name
     */
    public String friendly() {
        return friendly;
    }

    /**
     * Get key pair minimum size.
     *
     * @return Minimum size
     */
    public int minSize() {
        return minSize;
    }

    /**
     * Get key pair maximum size.
     *
     * @return Maximum size
     */
    public int maxSize() {
        return maxSize;
    }

    /**
     * Get key pair step size.
     *
     * @return Step size
     */
    public int stepSize() {
        return stepSize;
    }

    /**
     * Resolve the supplied JCE name to a matching Secret Key type.
     *
     * @param jce JCE name
     * @return Secret Key type or null if none
     */
    public static SecretKeyType resolveJce(String jce) {
        for (SecretKeyType secretKeyType : values()) {
            if (jce.equalsIgnoreCase(secretKeyType.jce())) {
                return secretKeyType;
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
