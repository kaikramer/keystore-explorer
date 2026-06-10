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
package org.kse.crypto.keystore.kdb;

import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.kse.crypto.keystore.kdb.asn1.Der;

/**
 * Encrypts a private key as a PKCS#8 {@code EncryptedPrivateKeyInfo} using PBES2
 * (PBKDF2-HMAC-SHA384 + AES-256-CBC) — the scheme the IBM CMS key-database format uses for private keys,
 * fully supported by the JDK.
 */
public final class Pbes2 {
    private static final String ALG = "PBEWithHmacSHA384AndAES_256";
    /** OID 1.2.840.113549.1.5.13 = id-PBES2. */
    private static final byte[] PBES2_OID =
        {0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x05, 0x0d};

    private Pbes2() {}

    /** DER of an EncryptedPrivateKeyInfo wrapping {@code key}, encrypted with {@code password}. */
    public static byte[] encrypt(PrivateKey key, char[] password) throws Exception {
        return encryptBytes(key.getEncoded(), password);
    }

    /** PBES2-encrypts arbitrary bytes, returning an EncryptedPrivateKeyInfo-shaped DER. */
    public static byte[] encryptBytes(byte[] plaintext, char[] password) throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALG);
        SecretKey sk = skf.generateSecret(new PBEKeySpec(password));
        Cipher c = Cipher.getInstance(ALG);
        c.init(Cipher.ENCRYPT_MODE, sk);
        byte[] enc = c.doFinal(plaintext);
        byte[] algId = Der.sequence(Der.encode(0x06, PBES2_OID), c.getParameters().getEncoded());
        return Der.sequence(algId, Der.encode(0x04, enc));
    }

    /** Decrypts an EncryptedPrivateKeyInfo-shaped DER back to its plaintext bytes. */
    public static byte[] decryptBytes(byte[] epkiDer, char[] password) throws Exception {
        javax.crypto.EncryptedPrivateKeyInfo epki = new javax.crypto.EncryptedPrivateKeyInfo(epkiDer);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(epki.getAlgName());
        SecretKey sk = skf.generateSecret(new PBEKeySpec(password));
        Cipher c = Cipher.getInstance(epki.getAlgName());
        c.init(Cipher.DECRYPT_MODE, sk, epki.getAlgParameters());
        return c.doFinal(epki.getEncryptedData());
    }
}
