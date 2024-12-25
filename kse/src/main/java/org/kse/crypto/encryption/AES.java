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
package org.kse.crypto.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.kse.gui.passwordmanager.EncryptionAlgorithm;

/**
 * Simplify AES encryption and decryption by wrapping the JCE calls
 */
public class AES {

    public static final int GCM_TAG_LEN = 128;

    /**
     * Encrypt with AES in CBC mode
     *
     * @param plainData Plain data to be encrypted
     * @param iv Initialization vector
     * @param aesKey The AES key
     * @return The encrypted data
     */
    public static byte[] encryptAesCbc(byte[] plainData, byte[] iv, SecretKey aesKey) {
        try {
            Cipher cipher = Cipher.getInstance(EncryptionAlgorithm.AES_CBC.getJceName());
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
            return cipher.doFinal(plainData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new EncryptionException(e);
        }
    }

    /**
     * Decrypt with AES in CBC mode
     *
     * @param encrData The encrypted data
     * @param iv Initialization vector
     * @param aesKey The AES key
     * @return The decrypted data
     */
    public static byte[] decryptAesCbc(byte[] encrData, byte[] iv, SecretKey aesKey) {
        try {
            Cipher cipher = Cipher.getInstance(EncryptionAlgorithm.AES_CBC.getJceName());
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            return cipher.doFinal(encrData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new EncryptionException(e);
        }
    }

    /**
     * Encrypt with AES in Galois/Counter Mode with 128-bit authentication tag (MAC)
     *
     * @param plainData Plain data to be encrypted
     * @param iv Initialization vector
     * @param aesKey The AES key
     * @return The encrypted data
     */
    public static byte[] encryptAesGcm(byte[] plainData, byte[] iv, SecretKey aesKey) {
        try {
            Cipher cipher = Cipher.getInstance(EncryptionAlgorithm.AES_GCM.getJceName());
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LEN, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            return cipher.doFinal(plainData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new EncryptionException(e);
        }
    }

    /**
     * Decrypt with AES in Galois/Counter Mode
     *
     * @param encrData The encrypted data
     * @param iv Initialization vector
     * @param aesKey The AES key
     * @return The decrypted data
     */
    public static byte[] decryptAesGcm(byte[] encrData, byte[] iv, SecretKey aesKey) {
        try {
            Cipher cipher = Cipher.getInstance(EncryptionAlgorithm.AES_GCM.getJceName());
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LEN, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
            return cipher.doFinal(encrData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new EncryptionException(e);
        }
    }

    /**
     * Generate a new AES key with the specified length.
     *
     * @param keyLength the length of the AES key in bits (e.g., 128, 192, 256)
     * @return the generated AES key
     */
    public static SecretKey generateKey(int keyLength) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keyLength);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("AES algorithm not available", e);
        }
    }

    /**
     * Create a SecretKey object from a byte array.
     *
     * @param decryptedKey the byte array to create the key from
     * @return the SecretKey object
     */
    public static SecretKey createKey(byte[] decryptedKey) {
        return new SecretKeySpec(decryptedKey, "AES");
    }
}
