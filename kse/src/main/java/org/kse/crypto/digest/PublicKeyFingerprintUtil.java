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

package org.kse.crypto.digest;

import java.security.PublicKey;

import org.kse.crypto.CryptoException;
import org.kse.crypto.publickey.KeyIdentifierGenerator;
import org.kse.crypto.publickey.OpenSslPubUtil;

/**
 * Helper class for calculating different fingerprint algorithms for public keys.
 */
public class PublicKeyFingerprintUtil {

    private PublicKeyFingerprintUtil() {
    }

    /**
     * Calculates the fingerprint of the given public key with the given algorithm.
     *
     * @param publicKey Public key for fingerprint calculation
     * @param algorithm How to calculate the fingerprint value
     * @return The fingerprint of the key
     */
    public static byte[] calculateFingerprint(PublicKey publicKey, PublicKeyFingerprintAlgorithm algorithm)
            throws CryptoException {

        // workaround for encoding bug in older Java versions
        PublicKey convertedPublicKey = OpenSslPubUtil.load(publicKey.getEncoded());

        KeyIdentifierGenerator keyIdentifierGenerator = new KeyIdentifierGenerator(convertedPublicKey);

        switch (algorithm) {
        case SKI_METHOD1:
            return keyIdentifierGenerator.generate160BitHashId();
        case SKI_METHOD2:
            return keyIdentifierGenerator.generate64BitHashId();
        case SHA1_OVER_SPKI:
            return DigestUtil.getMessageDigest(convertedPublicKey.getEncoded(), DigestType.SHA1);
        case SHA256_OVER_SPKI:
            return DigestUtil.getMessageDigest(convertedPublicKey.getEncoded(), DigestType.SHA256);
        default:
            throw new UnsupportedOperationException("Fingerprint algorithm not supported: " + algorithm.friendly());
        }
    }
}
