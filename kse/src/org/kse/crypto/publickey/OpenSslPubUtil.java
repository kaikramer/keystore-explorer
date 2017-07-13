/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
package org.kse.crypto.publickey;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ResourceBundle;

import org.kse.crypto.CryptoException;
import org.kse.utilities.io.ReadUtil;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

// @formatter:off
/**
 * Provides utility methods relating to OpenSSL encoded public keys.
 *
 * <pre>
 * OpenSSL Public Key structure:
 *
 *     SubjectPublicKeyInfo ::= ASN1Sequence {
 *         algorithm AlgorithmIdentifier,
 *         subjectPublicKey BIT STRING }
 *
 *     AlgorithmIdentifier ::= ASN1Sequence {
 *         algorithm OBJECT IDENTIFIER,
 *         parameters ANY DEFINED BY algorithm OPTIONAL }
 *
 *     Rsa-Parms ::= ASN1Null
 *
 *     Dss-Parms ::= ASN1Sequence {
 *         p ASN1Integer,
 *         q ASN1Integer,
 *         g ASN1Integer }
 *
 *     subjectPublicKey as DERBitString:
 *
 *     RSAPublicKey ::= ASN1Sequence {
 *         modulus ASN1Integer,
 *         publicExponent ASN1Integer}
 *
 *     DSAPublicKey ::= ASN1Integer
 * </pre>
 *
 */
// @formatter:on
public class OpenSslPubUtil {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/publickey/resources");

	private static final String OPENSSL_PUB_PEM_TYPE = "PUBLIC KEY";

	/**
	 * OpenSSL encode a public key.
	 *
	 * @return The encoding
	 * @param publicKey
	 *            The public key
	 */
	public static byte[] get(PublicKey publicKey) {
		// The public key encoding is a DER-encoded subjectPublicKeyInfo
		// structure - the OpenSSL format
		return publicKey.getEncoded();
	}

	/**
	 * OpenSSL encode a public key and PEM the encoding.
	 *
	 * @return The PEM'd encoding
	 * @param publicKey
	 *            The public key
	 */
	public static String getPem(PublicKey publicKey) {
		byte[] openSsl = get(publicKey);

		PemInfo pemInfo = new PemInfo(OPENSSL_PUB_PEM_TYPE, null, openSsl);
		String openSslPem = PemUtil.encode(pemInfo);

		return openSslPem;
	}

	/**
	 * Load an unencrypted OpenSSL public key from the stream. The encoding of
	 * the public key may be PEM or DER.
	 *
	 * @param is
	 *            Stream to load the unencrypted public key from
	 * @return The public key
	 * @throws CryptoException
	 *             Problem encountered while loading the public key
	 * @throws IOException
	 *             An I/O error occurred
	 */
	public static PublicKey load(InputStream is) throws CryptoException, IOException {
		byte[] streamContents = ReadUtil.readFully(is);

		// Check if stream is PEM encoded
		PemInfo pemInfo = PemUtil.decode(new ByteArrayInputStream(streamContents));

		if (pemInfo != null) {
			// It is - get DER from PEM
			streamContents = pemInfo.getContent();
		}

		try {
			// X509EncodedKeySpec accepts a DER-encoded subjectPublicKeyInfo
			// structure - the OpenSSL format
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(streamContents);

			// We have to specify a valid algorithm, but do not know which one
			PublicKey pubKey = null;
			try {
				pubKey = KeyFactory.getInstance("RSA").generatePublic(x509EncodedKeySpec);
			} catch (InvalidKeySpecException e) {
				// ok, not RSA, try DSA
				pubKey = KeyFactory.getInstance("DSA").generatePublic(x509EncodedKeySpec);
			}

			return pubKey;
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoLoadOpenSslPublicKey.exception.message"), ex);
		}
	}
}
