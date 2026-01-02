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
package org.kse.crypto.pbkd;

import static org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13;
import static org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id;
import static org.kse.KSE.BC;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Simplify use of PBKDF2 and Argon2 key derivation algorithms by wrapping the JCE/BC API calls
 */
public class PasswordBasedKeyDerivation {

    /**
     * Use PBKDF2 to derive an AES key
     *
     * @param password The password
     * @param salt Salt
     * @param iterations Number of iterations
     * @param keyLengthInBits Length of derived key
     * @return Derived AES key
     */
    public static SecretKey deriveKeyWithPbkdf2(char[] password, byte[] salt, int iterations, int keyLengthInBits) {
        try {
            var secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", BC);
            var pbeKeySpec = new PBEKeySpec(password, salt, iterations, keyLengthInBits);
            byte[] result = secretKeyFactory.generateSecret(pbeKeySpec).getEncoded();
            return new SecretKeySpec(result, "AES");
        } catch (RuntimeException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Use Argon2_id to derive an AES key
     *
     * @param password The password
     * @param salt Salt
     * @param iterations Number of iterations
     * @param memLimit Wanted memory usage
     * @param parallelism Wanted parallelism
     * @param keyLengthInBits Length of derived key
     * @return Derived AES key
     */
    public static SecretKey deriveKeyWithArgon2id(char[] password, byte[] salt, int iterations, int memLimit,
                                                  int parallelism, int keyLengthInBits) {
        var builder = new Argon2Parameters.Builder(ARGON2_id).withVersion(ARGON2_VERSION_13)
                                                             .withIterations(iterations)
                                                             .withMemoryAsKB(memLimit)
                                                             .withParallelism(parallelism)
                                                             .withSalt(salt);
        try {
            Argon2BytesGenerator generate = new Argon2BytesGenerator();
            generate.init(builder.build());
            byte[] result = new byte[keyLengthInBits / 8];
            generate.generateBytes(password, result);
            return new SecretKeySpec(result, "AES");
        } catch (RuntimeException e) {
            throw new RuntimeException(e);
        }
    }
}
