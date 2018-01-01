/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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

import static org.kse.crypto.KeyType.SYMMETRIC;
import static org.kse.crypto.SecurityProvider.BOUNCY_CASTLE;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;

public class SecretKeyUtil {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/secretkey/resources");

	private SecretKeyUtil() {
	}

	/**
	 * Generate a secret key.
	 *
	 * @param secretKeyType
	 *            Secret key type to generate
	 * @param keySize
	 *            Key size of secret key
	 * @return Secret key
	 * @throws CryptoException
	 *             If there was a problem generating the secret key
	 */
	public static SecretKey generateSecretKey(SecretKeyType secretKeyType, int keySize) throws CryptoException {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(secretKeyType.jce(), BOUNCY_CASTLE.jce());
			keyGenerator.init(keySize, SecureRandom.getInstance("SHA1PRNG"));

			return keyGenerator.generateKey();
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoGenerateSecretKey.exception.message"),
					secretKeyType), ex);
		}
	}

	/**
	 * Get the information about the supplied secret key.
	 *
	 * @param secretKey
	 *            The secret key
	 * @return Key information
	 */
	public static KeyInfo getKeyInfo(SecretKey secretKey) {
		String algorithm = secretKey.getAlgorithm();

		if (algorithm.equals("RC4")) {
			algorithm = "ARC4"; // RC4 is trademarked so we never want to
			// display it
		}

		if (secretKey.getFormat().equals("RAW")) {
			int keySize = secretKey.getEncoded().length * 8;
			return new KeyInfo(SYMMETRIC, algorithm, keySize);
		} else
			// Key size unknown
		{
			return new KeyInfo(SYMMETRIC, algorithm);
		}
	}
}
