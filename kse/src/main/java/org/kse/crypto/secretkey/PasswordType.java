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
import java.util.ResourceBundle;
import java.util.Set;

/**
 * An enumeration of the PBE (password based encryption) secret key factories.
 */
public enum PasswordType {

    PBEWITHHMACGOST3411("PBEWITHHMACGOST3411", "PasswordType.PbeWithHmacGost3411"),
    PBEWITHHMACRIPEMD160("PBEWITHHMACRIPEMD160", "PasswordType.PbeWithHmacRipemd160"),
    PBEWITHHMACSHA1("PBEWITHHMACSHA1", "PasswordType.PbeWithHmacSha1"),
    PBEWithHmacSHA1AndAES_128("PBEWithHmacSHA1AndAES_128", "PasswordType.PbeWithHmacSha1AndAes128"),
    PBEWithHmacSHA1AndAES_256("PBEWithHmacSHA1AndAES_256", "PasswordType.PbeWithHmacSha1AndAes256"),
    PBEWithHmacSHA224AndAES_128("PBEWithHmacSHA224AndAES_128", "PasswordType.PbeWithHmacSha224AndAes128"),
    PBEWithHmacSHA224AndAES_256("PBEWithHmacSHA224AndAES_256", "PasswordType.PbeWithHmacSha224AndAes256"),
    PBEWITHHMACSHA256("PBEWITHHMACSHA256", "PasswordType.PbeWithHmacSha256"),
    PBEWithHmacSHA256AndAES_128("PBEWithHmacSHA256AndAES_128", "PasswordType.PbeWithHmacSha256AndAes128"),
    PBEWithHmacSHA256AndAES_256("PBEWithHmacSHA256AndAES_256", "PasswordType.PbeWithHmacSha256AndAes256"),
    PBEWithHmacSHA384AndAES_128("PBEWithHmacSHA384AndAES_128", "PasswordType.PbeWithHmacSha384AndAes128"),
    PBEWithHmacSHA384AndAES_256("PBEWithHmacSHA384AndAES_256", "PasswordType.PbeWithHmacSha384AndAes256"),
    PBEWithHmacSHA512AndAES_128("PBEWithHmacSHA512AndAES_128", "PasswordType.PbeWithHmacSha512AndAes128"),
    PBEWithHmacSHA512AndAES_256("PBEWithHmacSHA512AndAES_256", "PasswordType.PbeWithHmacSha512AndAes256"),
    PBEWITHHMACTIGER("PBEWITHHMACTIGER", "PasswordType.PbeWithHmacTiger"),
    PBEWITHMD2ANDDES("PBEWITHMD2ANDDES", "PasswordType.PbeWithMD2AndDes"),
    PBEWITHMD2ANDRC2("PBEWITHMD2ANDRC2", "PasswordType.PbeWithMD2AndRC2"),
    PBEWITHMD5AND128BITAES_CBC_OPENSSL("PBEWITHMD5AND128BITAES-CBC-OPENSSL", "PasswordType.PbeWithMD5And128bitAesCbcOpenssl"),
    PBEWITHMD5AND192BITAES_CBC_OPENSSL("PBEWITHMD5AND192BITAES-CBC-OPENSSL", "PasswordType.PbeWithMD5And192bitAesCbcOpenssl"),
    PBEWITHMD5AND256BITAES_CBC_OPENSSL("PBEWITHMD5AND256BITAES-CBC-OPENSSL", "PasswordType.PbeWithMD5And256bitAesCbcOpenssl"),
    PBEWithMD5AndDES("PBEWithMD5AndDES", "PasswordType.PbeWithMD5AndDes"),
    PBEWithMD5AndTripleDES("PBEWithMD5AndTripleDES", "PasswordType.PbeWithMD5AndTripleDes"),
    PBEWITHMD5ANDRC2("PBEWITHMD5ANDRC2", "PasswordType.PbeWithMD5AndRC2"),
    PBEWITHSHAAND2_KEYTRIPLEDES_CBC("PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PasswordType.PbeWithShaAnd2KeyTripleDesCbc"),
    PBEWITHSHAAND3_KEYTRIPLEDES_CBC("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PasswordType.PbeWithShaAnd3KeyTripleDesCbc"),
    PBEWITHSHAAND128BITAES_CBC_BC("PBEWITHSHAAND128BITAES-CBC-BC", "PasswordType.PbeWithShaAnd128bitAesCbcBC"),
    PBEWITHSHAAND192BITAES_CBC_BC("PBEWITHSHAAND192BITAES-CBC-BC", "PasswordType.PbeWithShaAnd192bitAesCbcBC"),
    PBEWITHSHAAND256BITAES_CBC_BC("PBEWITHSHAAND256BITAES-CBC-BC", "PasswordType.PbeWithShaAnd256bitAesCbcBC"),
    PBEWITHSHA1ANDDES("PBEWITHSHA1ANDDES", "PasswordType.PbeWithSha1AndDes"),
    PBEWithSHA1AndDESede("PBEWithSHA1AndDESede", "PasswordType.PbeWithSha1AndDesede"),
    PBEWITHSHAANDIDEA_CBC("PBEWITHSHAANDIDEA-CBC", "PasswordType.PbeWithShaAndIdeaCbc"),
    PBEWITHSHA1ANDRC2("PBEWITHSHA1ANDRC2", "PasswordType.PbeWithSha1AndRC2"),
    PBEWithSHA1AndRC2_128("PBEWithSHA1AndRC2_128", "PasswordType.PbeWithSha1AndRC2128"),
    PBEWithSHA1AndRC2_40("PBEWithSHA1AndRC2_40", "PasswordType.PbeWithSha1AndRC240"),
    PBEWithSHA1AndRC4_128("PBEWithSHA1AndRC4_128", "PasswordType.PbeWithSha1AndRC4128"),
    PBEWITHSHAAND128BITRC4("PBEWITHSHAAND128BITRC4", "PasswordType.PbeWithShaAnd128bitRC4"),
    PBEWithSHA1AndRC4_40("PBEWithSHA1AndRC4_40", "PasswordType.PbeWithSha1AndRC440"),
    PBEWITHSHAANDTWOFISH_CBC("PBEWITHSHAANDTWOFISH-CBC", "PasswordType.PbeWithShaAndTwofishCbc"),
    PBEWITHSHA256AND128BITAES_CBC_BC("PBEWITHSHA256AND128BITAES-CBC-BC", "PasswordType.PbeWithSha256And128bitAesCbcBC"),
    PBEWITHSHA256AND192BITAES_CBC_BC("PBEWITHSHA256AND192BITAES-CBC-BC", "PasswordType.PbeWithSha256And192bitAesCbcBC"),
    PBEWITHSHA256AND256BITAES_CBC_BC("PBEWITHSHA256AND256BITAES-CBC-BC", "PasswordType.PbeWithSha256And256bitAesCbcBC");

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/secretkey/resources");

    // Supported sets of password algorithms. Located here so that they can be
    // referenced by the KeyStoreType enum.
    public static final Set<PasswordType> PASSWORD_ALL = EnumSet.allOf(PasswordType.class);

    public static final Set<PasswordType> PASSWORD_NONE = EnumSet.noneOf(PasswordType.class);

    public static final Set<PasswordType> PASSWORD_PKCS12 = EnumSet.of(PBEWithMD5AndDES,
            PBEWITHSHAAND3_KEYTRIPLEDES_CBC, PBEWithSHA1AndDESede, PBEWithSHA1AndRC2_128, PBEWithSHA1AndRC2_40,
            PBEWithSHA1AndRC4_128, PBEWITHSHAAND128BITRC4, PBEWithSHA1AndRC4_40);

    public static final Set<PasswordType> PASSWORD_BCFKS = EnumSet.of(PBEWithHmacSHA1AndAES_128,
            PBEWithHmacSHA1AndAES_256, PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256,
            PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256, PBEWithHmacSHA384AndAES_128,
            PBEWithHmacSHA384AndAES_256, PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256,
            PBEWITHMD5AND128BITAES_CBC_OPENSSL, PBEWITHMD5AND192BITAES_CBC_OPENSSL, PBEWITHMD5AND256BITAES_CBC_OPENSSL,
            PBEWITHSHAAND128BITAES_CBC_BC, PBEWITHSHAAND192BITAES_CBC_BC, PBEWITHSHAAND256BITAES_CBC_BC,
            PBEWITHSHA256AND128BITAES_CBC_BC, PBEWITHSHA256AND192BITAES_CBC_BC, PBEWITHSHA256AND256BITAES_CBC_BC);

    private String jce;
    private String friendlyKey;

    PasswordType(String jce, String friendly) {
        this.jce = jce;
        this.friendlyKey = friendly;
    }

    /**
     * Get password type JCE name.
     *
     * @return JCE name
     */
    public String jce() {
        return jce;
    }

    /**
     * Get password type friendly name.
     *
     * @return Friendly name
     */
    public String friendly() {
        return res.getString(friendlyKey);
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

    /**
     * Returns friendly name.
     *
     * @return Friendly name
     */
    @Override
    public String toString() {
        return friendly();
    }

    // Method for quickly identifying the PBE algorithms supported by KeyStoreType.
    // It prints out the enum name making it easy to update the EnumSets.
//    public static void main(String[] args) throws Exception {
//        try {
//            byte[] pass = "testpassword".getBytes();
//            char[] keypass = "password".toCharArray();
//            KeyStore ks = KeyStore.getInstance("BCFKS");
//            System.out.println("Type: " + ks.getType());
//            ks.load(null);
//            for (PasswordType pt : PasswordType.values()) {
//                try {
//                    ks.setKeyEntry(pt.friendly(), new SecretKeySpec(pass, pt.jce()), keypass, null);
//                    ks.getKey(pt.friendly(), keypass);
//                    System.out.println(pt.name());
//                } catch (Exception e) {
//
//                }
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
}
