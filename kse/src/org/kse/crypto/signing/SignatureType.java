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
package org.kse.crypto.signing;

import static org.kse.crypto.digest.DigestType.MD2;
import static org.kse.crypto.digest.DigestType.MD5;
import static org.kse.crypto.digest.DigestType.RIPEMD128;
import static org.kse.crypto.digest.DigestType.RIPEMD160;
import static org.kse.crypto.digest.DigestType.RIPEMD256;
import static org.kse.crypto.digest.DigestType.SHA1;
import static org.kse.crypto.digest.DigestType.SHA224;
import static org.kse.crypto.digest.DigestType.SHA256;
import static org.kse.crypto.digest.DigestType.SHA384;
import static org.kse.crypto.digest.DigestType.SHA512;

import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import org.kse.crypto.digest.DigestType;

/**
 * Enumeration of Signature Types supported by the X509CertUtil class.
 *
 */
public enum SignatureType {

	// @formatter:off
	SHA1_DSA("SHA1withDSA", "1.2.840.10040.4.3", SHA1, "SignatureType.Sha1WithDsa"),
	SHA224_DSA("SHA224withDSA", "2.16.840.1.101.3.4.3.1", SHA224, "SignatureType.Sha224WithDsa"),
	SHA256_DSA("SHA256withDSA", "2.16.840.1.101.3.4.3.2", SHA256, "SignatureType.Sha256WithDsa"),
	SHA384_DSA("SHA384withDSA", "2.16.840.1.101.3.4.3.3", SHA384, "SignatureType.Sha384WithDsa"),
	SHA512_DSA("SHA512withDSA", "2.16.840.1.101.3.4.3.4", SHA512, "SignatureType.Sha512WithDsa"),

	MD2_RSA("MD2withRSA", "1.2.840.113549.1.1.2", MD2, "SignatureType.Md2WithRsa"),
	MD5_RSA("MD5withRSA", "1.2.840.113549.1.1.4", MD5, "SignatureType.Md5WithRsa"),
	RIPEMD128_RSA("RIPEMD128withRSA", "1.3.36.3.3.1.3", RIPEMD128, "SignatureType.Ripemd128WithRsa"),
	RIPEMD160_RSA("RIPEMD160withRSA", "1.3.36.3.3.1.2", RIPEMD160, "SignatureType.Ripemd160WithRsa"),
	RIPEMD256_RSA("RIPEMD256withRSA", "1.3.36.3.3.1.4", RIPEMD256, "SignatureType.Ripemd256WithRsa"),
	SHA1_RSA("SHA1withRSA", "1.2.840.113549.1.1.5", SHA1, "SignatureType.Sha1WithRsa"),
	SHA224_RSA("SHA224withRSA", "1.2.840.113549.1.1.14", SHA224, "SignatureType.Sha224WithRsa"),
	SHA256_RSA("SHA256withRSA", "1.2.840.113549.1.1.11", SHA256, "SignatureType.Sha256WithRsa"),
	SHA384_RSA("SHA384withRSA", "1.2.840.113549.1.1.12", SHA384, "SignatureType.Sha384WithRsa"),
	SHA512_RSA("SHA512withRSA", "1.2.840.113549.1.1.13", SHA512, "SignatureType.Sha512WithRsa"),

	SHA1_ECDSA("SHA1withECDSA", "1.2.840.10045.4.1", SHA1, "SignatureType.Sha1WithEcDsa"),
	SHA224_ECDSA("SHA224withECDSA", "1.2.840.10045.4.3.1", SHA224, "SignatureType.Sha224WithEcDsa"),
	SHA256_ECDSA("SHA256withECDSA", "1.2.840.10045.4.3.2", SHA256, "SignatureType.Sha256WithEcDsa"),
	SHA384_ECDSA("SHA384withECDSA", "1.2.840.10045.4.3.3", SHA384, "SignatureType.Sha384WithEcDsa"),
	SHA512_ECDSA("SHA512withECDSA", "1.2.840.10045.4.3.4", SHA512, "SignatureType.Sha512WithEcDsa");
	// @formatter:on

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/signing/resources");
	private String jce;
	private String oid;
	private DigestType digestType;
	private String friendlyKey;

	SignatureType(String jce, String oid, DigestType digestType, String friendlyKey) {
		this.jce = jce;
		this.oid = oid;
		this.digestType = digestType;
		this.friendlyKey = friendlyKey;
	}

	/**
	 * Get signature type JCE name.
	 *
	 * @return JCE name
	 */
	public String jce() {
		return jce;
	}

	/**
	 * Get signature type Object Identifier.
	 *
	 * @return Object Identifier
	 */
	public String oid() {
		return oid;
	}

	/**
	 * Get signature type's digest type.
	 *
	 * @return Digest type
	 */
	public DigestType digestType() {
		return digestType;
	}

	/**
	 * Get type's friendly name.
	 *
	 * @return Friendly name
	 */
	public String friendly() {
		return res.getString(friendlyKey);
	}

	/**
	 * Get the signature types compatible with DSA.
	 *
	 * @return DSA signature types
	 */
	public static List<SignatureType> dsaSignatureTypes() {
		List<SignatureType> signatureTypes = new ArrayList<SignatureType>();

		signatureTypes.add(SHA1_DSA);
		signatureTypes.add(SHA224_DSA);
		signatureTypes.add(SHA256_DSA);
		signatureTypes.add(SHA384_DSA);
		signatureTypes.add(SHA512_DSA);

		return signatureTypes;
	}

	/**
	 * Get the signature types compatible with ECDSA.
	 *
	 * @return ECDSA signature types
	 */
	public static List<SignatureType> ecdsaSignatureTypes() {
		List<SignatureType> signatureTypes = new ArrayList<SignatureType>();

		signatureTypes.add(SHA1_ECDSA);
		//signatureTypes.add(SHA224_ECDSA); // not supported by Sun provider
		signatureTypes.add(SHA256_ECDSA);
		signatureTypes.add(SHA384_ECDSA);
		signatureTypes.add(SHA512_ECDSA);

		return signatureTypes;
	}

	/**
	 * Get the signature types compatible with RSA.
	 *
	 * @return RSA signature types
	 */
	public static List<SignatureType> rsaSignatureTypes() {
		List<SignatureType> signatureTypes = new ArrayList<SignatureType>();

		signatureTypes.add(MD2_RSA);
		signatureTypes.add(MD5_RSA);
		signatureTypes.add(RIPEMD128_RSA);
		signatureTypes.add(RIPEMD160_RSA);
		signatureTypes.add(RIPEMD256_RSA);
		signatureTypes.add(SHA1_RSA);
		signatureTypes.add(SHA224_RSA);
		signatureTypes.add(SHA256_RSA);
		signatureTypes.add(SHA384_RSA);
		signatureTypes.add(SHA512_RSA);

		return signatureTypes;
	}

	/**
	 * Get the signature types compatible with RSA at the supplied key size.
	 *
	 * @param keySize
	 *            Key size in bits
	 * @return RSA signature types
	 */
	public static List<SignatureType> rsaSignatureTypes(int keySize) {
		List<SignatureType> signatureTypes = rsaSignatureTypes();

		// SHA-512 requires RSA key length 512 + 233 bits padding, round up to nearest power of 8
		if (keySize < 752) {
			signatureTypes.remove(SHA512_RSA);
		}

		// SHA-384 requires RSA key length 384 + 233 bits padding, round up to nearest power of 8
		if (keySize < 624) {
			signatureTypes.remove(SHA384_RSA);
		}

		return signatureTypes;
	}

	/**
	 * Resolve the supplied JCE name to a matching Signature type.
	 *
	 * @param jce
	 *            JCE name
	 * @return Signature type or null if none
	 */
	public static SignatureType resolveJce(String jce) {
		for (SignatureType signatureType : values()) {
			if (jce.equals(signatureType.jce())) {
				return signatureType;
			}
		}

		return null;
	}

	/**
	 * Resolve the supplied object identifier to a matching Signature type.
	 *
	 * @param oid
	 *            Object identifier
	 * @return Signature type or null if none
	 */
	public static SignatureType resolveOid(String oid) {
		for (SignatureType signatureType : values()) {
			if (oid.equals(signatureType.oid())) {
				return signatureType;
			}
		}

		return null;
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
}
