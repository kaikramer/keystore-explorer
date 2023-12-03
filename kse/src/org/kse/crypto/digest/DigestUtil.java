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

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import org.apache.commons.io.IOUtils;
import org.kse.crypto.CryptoException;
import org.kse.utilities.io.HexUtil;

/**
 * Provides utility methods for the creation of message digests.
 */
public final class DigestUtil {
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/digest/resources");

    private DigestUtil() {
    }

    /**
     * Get a digest of the input stream.
     *
     * @param istream    Input stream to digest
     * @param digestType The message digest algorithm
     * @return The message digest
     * @throws CryptoException If message digester could not be created
     */
    public static byte[] getMessageDigest(InputStream istream, DigestType digestType) throws CryptoException {
        MessageDigest messageDigester = getMessageDigester(digestType);

        try {
            byte[] buffer = new byte[2048];
            int read = 0;

            while ((read = istream.read(buffer)) != -1) {
                messageDigester.update(buffer, 0, read);
            }

            return messageDigester.digest();
        } catch (IOException ex) {
            throw new CryptoException(res.getString("NoCreateDigest.exception.message"), ex);
        } finally {
            IOUtils.closeQuietly(istream);
        }
    }

    /**
     * Get a digest of the supplied message.
     *
     * @param message    The message to digest
     * @param digestType The message digest algorithm
     * @return The message digest
     * @throws CryptoException If message digester could not be created
     */
    public static byte[] getMessageDigest(byte[] message, DigestType digestType) throws CryptoException {
        MessageDigest messageDigester = getMessageDigester(digestType);

        return messageDigester.digest(message);
    }

    /**
     * Get the digest of a message as a formatted String. Returned in base-16
     * with ':' separators every two characters padded with a leading 0 if
     * necessary to make for an even number of hex characters.
     *
     * @param message    The message to digest
     * @param digestType The message digest algorithm
     * @return The message digest
     * @throws CryptoException If message digester could not be created
     */
    public static String getFriendlyMessageDigest(byte[] message, DigestType digestType) throws CryptoException {
        byte[] messageDigest = getMessageDigest(message, digestType);

        return HexUtil.getHexStringWithSep(messageDigest, ':');
    }

    /**
     * Create message digester of supplied type.
     *
     * @param digestType Digest type
     * @return Message digester
     * @throws CryptoException If message digester could not be created
     */
    public static MessageDigest getMessageDigester(DigestType digestType) throws CryptoException {
        try {
            return MessageDigest.getInstance(digestType.jce());
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(
                    MessageFormat.format(res.getString("NoCreateDigester.exception.message"), digestType.jce()), ex);
        }
    }
}
