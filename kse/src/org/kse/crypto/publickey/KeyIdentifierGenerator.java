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

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;

/**
 * Generator for public key identifiers of various forms.
 *
 */
public class KeyIdentifierGenerator {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/publickey/resources");

	private PublicKey publicKey;

	/**
	 * Construct KeyIdentifierGenerator.
	 *
	 * @param publicKey
	 *            Public key to generate identifiers for
	 */
	public KeyIdentifierGenerator(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * Generate 160 bit hash key identifier.
	 *
	 * @return Key identifier
	 * @throws CryptoException
	 *             If generation fails
	 */
	public byte[] generate160BitHashId() throws CryptoException {
		/*
		 * RFC 3280: The keyIdentifier is composed of the 160-bit SHA-1 hash of
		 * the value of the BIT STRING subjectPublicKey (excluding the tag,
		 * length, and number of unused bits)
		 */

		try {
			DERBitString publicKeyBitString = encodePublicKeyAsBitString(publicKey);
			return DigestUtil.getMessageDigest(publicKeyBitString.getBytes(), DigestType.SHA1);
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoGenerateKeyIdentifier.exception.message"), ex);
		}
	}

	/**
	 * Generate 64 bit hash key identifier.
	 *
	 * @return Key identifier
	 * @throws CryptoException
	 *             If generation fails
	 */
	public byte[] generate64BitHashId() throws CryptoException {
		/*
		 * RFC 3280: The keyIdentifier is composed of a four bit type field with
		 * the value 0100 followed by the least significant 60 bits of the SHA-1
		 * hash of the value of the BIT STRING subjectPublicKey (excluding the
		 * tag, length, and number of unused bit string bits)
		 */

		try {
			DERBitString publicKeyBitString = encodePublicKeyAsBitString(publicKey);
			byte[] hash = DigestUtil.getMessageDigest(publicKeyBitString.getBytes(), DigestType.SHA1);
			byte[] subHash = Arrays.copyOfRange(hash, 12, 20);
			subHash[0] &= 0x0F;
			subHash[0] |= 0x40;

			return subHash;
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoGenerateKeyIdentifier.exception.message"), ex);
		}
	}

	private DERBitString encodePublicKeyAsBitString(PublicKey publicKey) throws IOException {
		byte[] encodedPublicKey;

		if (publicKey instanceof RSAPublicKey) {
			encodedPublicKey = encodeRsaPublicKeyAsBitString((RSAPublicKey) publicKey);
		} else if (publicKey instanceof ECPublicKey){
			encodedPublicKey = encodeEcPublicKeyAsBitString((ECPublicKey) publicKey);
		} else {
			encodedPublicKey = encodeDsaPublicKeyAsBitString((DSAPublicKey) publicKey);
		}

		return new DERBitString(encodedPublicKey);
	}


	private byte[] encodeRsaPublicKeyAsBitString(RSAPublicKey rsaPublicKey) throws IOException {
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(new ASN1Integer(rsaPublicKey.getModulus()));
		vec.add(new ASN1Integer(rsaPublicKey.getPublicExponent()));

		DERSequence derSequence = new DERSequence(vec);
		return derSequence.getEncoded();
	}

	private byte[] encodeEcPublicKeyAsBitString(ECPublicKey ecPublicKey) {
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(ecPublicKey.getEncoded());
		byte[] bytes = publicKeyInfo.getPublicKeyData().getBytes();
		return bytes;
	}

	private byte[] encodeDsaPublicKeyAsBitString(DSAPublicKey dsaPublicKey) throws IOException {
		ASN1Integer publicKey = new ASN1Integer(dsaPublicKey.getY());

		return publicKey.getEncoded(ASN1Encoding.DER);
	}
}
