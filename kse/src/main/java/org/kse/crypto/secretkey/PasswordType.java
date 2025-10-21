/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

import java.util.EnumSet;
import java.util.Set;

/**
 * An enumeration of the PBE (password based encryption) secret key factories.
 */
public enum PasswordType {
    PBEWITHHMACGOST3411("PBEWITHHMACGOST3411", "PBE with HMac-GOST3411"),
    PBEWITHHMACRIPEMD160("PBEWITHHMACRIPEMD160", "PBE with HMac-RipeMD160"),
    PBEWITHHMACSHA1("PBEWITHHMACSHA1", "PBE with HMac-SHA-1"),
    PBEWithHmacSHA1AndAES_128("PBEWithHmacSHA1AndAES_128", "PBE with HMac-SHA-1 and AES-128"),
    PBEWithHmacSHA1AndAES_256("PBEWithHmacSHA1AndAES_256", "PBE with HMac-SHA-1 and AES-256"),
    PBEWithHmacSHA224AndAES_128("PBEWithHmacSHA224AndAES_128", "PBE with HMac-SHA-224 and AES-128"),
    PBEWithHmacSHA224AndAES_256("PBEWithHmacSHA224AndAES_256", "PBE with HMac-SHA-224 and AES-256"),
    PBEWITHHMACSHA256("PBEWITHHMACSHA256", "PBE with HMac-SHA-256"),
    PBEWithHmacSHA256AndAES_128("PBEWithHmacSHA256AndAES_128", "PBE with HMac-SHA-256 and AES-128"),
    PBEWithHmacSHA256AndAES_256("PBEWithHmacSHA256AndAES_256", "PBE with HMac-SHA-256 and AES-256"),
    PBEWithHmacSHA384AndAES_128("PBEWithHmacSHA384AndAES_128", "PBE with HMac-SHA-384 and AES-128"),
    PBEWithHmacSHA384AndAES_256("PBEWithHmacSHA384AndAES_256", "PBE with HMac-SHA-384 and AES-256"),
    PBEWithHmacSHA512AndAES_128("PBEWithHmacSHA512AndAES_128", "PBE with HMac-SHA-512 and AES-128"),
    PBEWithHmacSHA512AndAES_256("PBEWithHmacSHA512AndAES_256", "PBE with HMac-SHA-512 and AES-256"),
    PBEWITHHMACTIGER("PBEWITHHMACTIGER", "PBE with HMac-TIGER"),
    PBEWITHMD2ANDDES("PBEWITHMD2ANDDES", "PBE with MD2 and DES"),
    PBEWITHMD2ANDRC2("PBEWITHMD2ANDRC2", "PBE with MD2 and RC2"),
    PBEWITHMD5AND128BITAES_CBC_OPENSSL("PBEWITHMD5AND128BITAES-CBC-OPENSSL", "PBE with MD5 and AES-128 CBC OpenSSL"),
    PBEWITHMD5AND192BITAES_CBC_OPENSSL("PBEWITHMD5AND192BITAES-CBC-OPENSSL", "PBE with MD5 and AES-192 CBC OpenSSL"),
    PBEWITHMD5AND256BITAES_CBC_OPENSSL("PBEWITHMD5AND256BITAES-CBC-OPENSSL", "PBE with MD5 and AES-256 CBC OpenSSL"),
    PBEWithMD5AndDES("PBEWithMD5AndDES", "PBE with MD5 and DES"),
    PBEWithMD5AndTripleDES("PBEWithMD5AndTripleDES", "PBE with MD5 and DESede"),
    PBEWITHMD5ANDRC2("PBEWITHMD5ANDRC2", "PBE with MD5 and RC2"),
    PBEWITHSHAAND2_KEYTRIPLEDES_CBC("PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PBE with SHA-1 and 2-key TripleDES CBC"),
    PBEWITHSHAAND3_KEYTRIPLEDES_CBC("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PBE with SHA-1 and 3-key TripleDES CBC"),
    PBEWITHSHAAND128BITAES_CBC_BC("PBEWITHSHAAND128BITAES-CBC-BC", "PBE with SHA-1 and AES-128 CBC BC"),
    PBEWITHSHAAND192BITAES_CBC_BC("PBEWITHSHAAND192BITAES-CBC-BC", "PBE with SHA-1 and AES-192 CBC BC"),
    PBEWITHSHAAND256BITAES_CBC_BC("PBEWITHSHAAND256BITAES-CBC-BC", "PBE with SHA-1 and AES-256 CBC BC"),
    PBEWITHSHA1ANDDES("PBEWITHSHA1ANDDES", "PBE with SHA-1 and DES"),
    PBEWithSHA1AndDESede("PBEWithSHA1AndDESede", "PBE with SHA-1 and DESede"),
    PBEWITHSHAANDIDEA_CBC("PBEWITHSHAANDIDEA-CBC", "PBE with SHA-1 and IDEA CBC"),
    PBEWITHSHA1ANDRC2("PBEWITHSHA1ANDRC2", "PBE with SHA-1 and RC2"),
    PBEWithSHA1AndRC2_128("PBEWithSHA1AndRC2_128", "PBE with SHA-1 and RC2-128"),
    PBEWithSHA1AndRC2_40("PBEWithSHA1AndRC2_40", "PBE with SHA-1 and RC2-40"),
    PBEWithSHA1AndRC4_128("PBEWithSHA1AndRC4_128", "PBE with SHA-1 and RC4-128"),
    PBEWITHSHAAND128BITRC4("PBEWITHSHAAND128BITRC4", "PBE with SHA-1 and RC4-128 CBC"),
    PBEWithSHA1AndRC4_40("PBEWithSHA1AndRC4_40", "PBE with SHA-1 and RC4-40"),
    PBEWITHSHAANDTWOFISH_CBC("PBEWITHSHAANDTWOFISH-CBC", "PBE with SHA-1 and Twofish CBC"),
    PBEWITHSHA256AND128BITAES_CBC_BC("PBEWITHSHA256AND128BITAES-CBC-BC", "PBE with SHA-256 and AES-128 CBC BC"),
    PBEWITHSHA256AND192BITAES_CBC_BC("PBEWITHSHA256AND192BITAES-CBC-BC", "PBE with SHA-256 and AES-192 CBC BC"),
    PBEWITHSHA256AND256BITAES_CBC_BC("PBEWITHSHA256AND256BITAES-CBC-BC", "PBE with SHA-256 and AES-256 CBC BC");

    // Supported sets of password algorithms. Located here so that they can be
    // referenced by the KeyStoreType enum.
    public static final Set<PasswordType> PASSWORD_ALL = EnumSet.allOf(PasswordType.class);

    public static final Set<PasswordType> PASSWORD_NONE = EnumSet.noneOf(PasswordType.class);

//    public static final Set<PasswordType> PASSWORD_PKCS12 = EnumSet.of(AES, BLOWFISH, CAMELLIA, CAST5, DES,
//            HMAC_SHA1, HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512, ARC4, SEED);
//
//    public static final Set<PasswordType> PASSWORD_BCFKS = EnumSet.of(AES, DESEDE, HMAC_SHA1, HMAC_SHA224,
//            HMAC_SHA256, HMAC_SHA384, HMAC_SHA512, SEED);

    private String jce;
    private String friendly;

    PasswordType(String jce, String friendly) {
        this.jce = jce;
        this.friendly = friendly;
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
     * Resolve the supplied JCE name to a matching Password type.
     *
     * @param jce JCE name
     * @return Password type or null if none
     */
    public static PasswordType resolveJce(String jce) {
        for (PasswordType passwordType : values()) {
            if (jce.equalsIgnoreCase(passwordType.jce())) {
                return passwordType;
            }
        }

        return null;
    }

    /**
     * Determines if the supplied JCE name is a password. Using this method
     * will identify any future PBE algorithms that might be added in the future
     * but not added to PasswordType. If resolveJce is used to identify a PBE
     * algorithm, then KSE would treat new PBE algorithms as SecretKey types
     * until PasswordType is updated.
     *
     * @param jce JCE name
     * @return True if the JCE name is a password. False if it is a key.
     */
    public static boolean isPassword(String jce) {
        return jce.startsWith("PBE");
    }
}
