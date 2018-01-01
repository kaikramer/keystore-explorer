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
package org.kse.crypto.publickey;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.kse.crypto.CryptoException;
import org.kse.utilities.io.ReadUtil;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

// @formatter:off
/**
 * Provides utility methods relating to OpenSSL/SubjectPublicKeyInfo encoded public keys. The PKCS#1 RSA public key
 * format is not supported.
 *
 * <pre>
 * -----BEGIN PUBLIC KEY-----
 * ...
 * -----END PUBLIC KEY-----
 * </pre>
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
 *     ECParameters ::= CHOICE {                      // RFC 5480
 *         namedCurve         OBJECT IDENTIFIER
 *         -- implicitCurve   NULL
 *         -- specifiedCurve  SpecifiedECDomain }
 *
 *     subjectPublicKey as DERBitString:
 *
 *     RSAPublicKey ::= ASN1Sequence {
 *         modulus ASN1Integer,
 *         publicExponent ASN1Integer}
 *
 *     DSAPublicKey ::= ASN1Integer
 *
 *     ECPoint ::= OCTET STRING
 * </pre>
 *
 */
// @formatter:on
public class OpenSslPubUtil {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/publickey/resources");

	private static final String OPENSSL_PUB_PEM_TYPE = "PUBLIC KEY";

	private OpenSslPubUtil() {
	}

	/**
	 * OpenSSL encode a public key.
	 *
	 * @return The encoding
	 * @param publicKey
	 *            The public key
	 */
	public static byte[] get(PublicKey publicKey) {
		// The public key encoding is a DER-encoded subjectPublicKeyInfo structure - the OpenSSL format
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
			// DER-encoded subjectPublicKeyInfo structure - the OpenSSL format
			SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(streamContents);
			return new JcaPEMKeyConverter().getPublicKey(publicKeyInfo);
		} catch (Exception ex) {
			throw new CryptoException(res.getString("NoLoadOpenSslPublicKey.exception.message"), ex);
		}
	}
}
