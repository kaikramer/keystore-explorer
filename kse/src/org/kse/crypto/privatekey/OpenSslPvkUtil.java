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
package org.kse.crypto.privatekey;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.kse.crypto.privatekey.EncryptionType.ENCRYPTED;
import static org.kse.crypto.privatekey.EncryptionType.UNENCRYPTED;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.text.MessageFormat;
import java.util.Calendar;
import java.util.Random;
import java.util.ResourceBundle;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;
import org.kse.crypto.ecc.EccUtil;
import org.kse.utilities.io.ReadUtil;
import org.kse.utilities.pem.PemAttribute;
import org.kse.utilities.pem.PemAttributes;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

/**
 * Provides utility methods relating to OpenSSL encoded private keys.
 *
 */
public class OpenSslPvkUtil {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/privatekey/resources");

	// Begin OpenSSL RSA private key PEM
	private static final String OPENSSL_RSA_PVK_PEM_TYPE = "RSA PRIVATE KEY";

	// Begin OpenSSL DSA private key PEM
	private static final String OPENSSL_DSA_PVK_PEM_TYPE = "DSA PRIVATE KEY";

	// Begin OpenSSL EC private key PEM
	private static final String OPENSSL_EC_PVK_PEM_TYPE = "EC PRIVATE KEY";

	// OpenSSL version
	private static final BigInteger VERSION = BigInteger.ZERO;

	// EC private key ASN.1 structure has version 1
	private static final BigInteger VERSION_EC = BigInteger.ONE;

	// Proc-Type PEM header attribute name
	private static final String PROC_TYPE_ATTR_NAME = "Proc-Type";

	// Proc-Type PEM header attribute value
	private static final String PROC_TYPE_ATTR_VALUE = "4,ENCRYPTED";

	// DEK-Info PEM header attribute name
	private static final String DEK_INFO_ATTR_NAME = "DEK-Info";

	// DEK-Info PEM headere attribute value template (pbe algorithm,salt)
	private static final String DEK_INFO_ATTR_VALUE_TEMPLATE = "{0},{1}";

	private OpenSslPvkUtil() {
	}

	/**
	 * OpenSSL encode a private key.
	 *
	 * @return The encoding
	 * @param privateKey
	 *            The private key
	 * @throws CryptoException
	 *             Problem encountered while getting the encoded private key
	 */
	public static byte[] get(PrivateKey privateKey) throws CryptoException {
		// DER encoding for each key type is a sequence
		ASN1EncodableVector vec = new ASN1EncodableVector();

		if (privateKey instanceof ECPrivateKey) {
			try {
				ECPrivateKey ecPrivKey = (ECPrivateKey) privateKey;
				org.bouncycastle.asn1.sec.ECPrivateKey keyStructure = EccUtil.convertToECPrivateKeyStructure(ecPrivKey);
				return keyStructure.toASN1Primitive().getEncoded();
			} catch (IOException e) {
				throw new CryptoException(res.getString("NoDerEncodeOpenSslPrivateKey.exception.message"), e);
			}
		} else if (privateKey instanceof RSAPrivateCrtKey) {
			RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;

			vec.add(new ASN1Integer(VERSION));
			vec.add(new ASN1Integer(rsaPrivateKey.getModulus()));
			vec.add(new ASN1Integer(rsaPrivateKey.getPublicExponent()));
			vec.add(new ASN1Integer(rsaPrivateKey.getPrivateExponent()));
			vec.add(new ASN1Integer(rsaPrivateKey.getPrimeP()));
			vec.add(new ASN1Integer(rsaPrivateKey.getPrimeQ()));
			vec.add(new ASN1Integer(rsaPrivateKey.getPrimeExponentP()));
			vec.add(new ASN1Integer(rsaPrivateKey.getPrimeExponentQ()));
			vec.add(new ASN1Integer(rsaPrivateKey.getCrtCoefficient()));
		} else {
			DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) privateKey;
			DSAParams dsaParams = dsaPrivateKey.getParams();

			BigInteger primeModulusP = dsaParams.getP();
			BigInteger primeQ = dsaParams.getQ();
			BigInteger generatorG = dsaParams.getG();
			BigInteger secretExponentX = dsaPrivateKey.getX();

			// Derive public key from private key parts, ie Y = G^X mod P
			BigInteger publicExponentY = generatorG.modPow(secretExponentX, primeModulusP);

			vec.add(new ASN1Integer(VERSION));
			vec.add(new ASN1Integer(primeModulusP));
			vec.add(new ASN1Integer(primeQ));
			vec.add(new ASN1Integer(generatorG));
			vec.add(new ASN1Integer(publicExponentY));
			vec.add(new ASN1Integer(secretExponentX));
		}
		DERSequence derSequence = new DERSequence(vec);

		try {
			return derSequence.getEncoded();
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoDerEncodeOpenSslPrivateKey.exception.message"), ex);
		}
	}

	/**
	 * OpenSSL encode a private key and PEM the encoding.
	 *
	 * @return The PEM'd encoding
	 * @param privateKey
	 *            The private key
	 * @throws CryptoException
	 *             Problem encountered while getting the encoded private key
	 */
	public static String getPem(PrivateKey privateKey) throws CryptoException {
		byte[] openSsl = get(privateKey);

		String pemType = null;

		if (privateKey instanceof RSAPrivateCrtKey) {
			pemType = OPENSSL_RSA_PVK_PEM_TYPE;
		} else if (privateKey instanceof ECPrivateKey) {
			pemType = OPENSSL_EC_PVK_PEM_TYPE;
		} else {
			pemType = OPENSSL_DSA_PVK_PEM_TYPE;
		}

		PemInfo pemInfo = new PemInfo(pemType, null, openSsl);
		String openSslPem = PemUtil.encode(pemInfo);

		return openSslPem;
	}

	/**
	 * OpenSSL encode and encrypt a private key. Encrypted OpenSSL private keys
	 * must always by PEM'd.
	 *
	 * @return The encrypted, PEM'd encoding
	 * @param privateKey
	 *            The private key
	 * @param pbeType
	 *            PBE algorithm to use for encryption
	 * @param password
	 *            Encryption password
	 * @throws CryptoException
	 *             Problem encountered while getting the encoded private key
	 */
	public static String getEncrypted(PrivateKey privateKey, OpenSslPbeType pbeType, Password password)
			throws CryptoException {
		byte[] openSsl = get(privateKey);

		String pemType = null;

		if (privateKey instanceof RSAPrivateCrtKey) {
			pemType = OPENSSL_RSA_PVK_PEM_TYPE;
		} else if (privateKey instanceof ECPrivateKey) {
			pemType = OPENSSL_EC_PVK_PEM_TYPE;
		} else {
			pemType = OPENSSL_DSA_PVK_PEM_TYPE;
		}

		byte[] salt = generateSalt(pbeType.saltSize() / 8);

		String saltHex = bytesToHex(salt);

		byte[] encOpenSsl = null;

		try {
			byte[] encryptKey = deriveKeyFromPassword(password, salt, pbeType.keySize());

			// Create cipher - use all of the salt as the IV
			Cipher cipher = createCipher(pbeType.jceCipher(), encryptKey, salt, ENCRYPT_MODE);

			encOpenSsl = cipher.doFinal(openSsl);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(MessageFormat.format("OpenSslEncryptionFailed.exception.message",
					pbeType.friendly()), ex);
		}

		PemAttributes attributes = new PemAttributes();

		attributes.add(new PemAttribute(PROC_TYPE_ATTR_NAME, PROC_TYPE_ATTR_VALUE));

		String dekInfoAttrValue = MessageFormat.format(DEK_INFO_ATTR_VALUE_TEMPLATE, pbeType.dekInfo(), saltHex);
		attributes.add(new PemAttribute(DEK_INFO_ATTR_NAME, dekInfoAttrValue));

		PemInfo pemInfo = new PemInfo(pemType, attributes, encOpenSsl);

		return PemUtil.encode(pemInfo);
	}

	/**
	 * Load an unencrypted OpenSSL private key from the stream. The encoding of
	 * the private key may be PEM or DER.
	 *
	 * @param is
	 *            Stream to load the unencrypted private key from
	 * @return The private key
	 * @throws PrivateKeyEncryptedException
	 *             If private key is encrypted
	 * @throws CryptoException
	 *             Problem encountered while loading the private key
	 * @throws IOException
	 *             An I/O error occurred
	 */
	public static PrivateKey load(InputStream is) throws CryptoException, IOException {
		byte[] streamContents = ReadUtil.readFully(is);

		EncryptionType encType = getEncryptionType(new ByteArrayInputStream(streamContents));

		if (encType == null) {
			throw new CryptoException(res.getString("NotValidOpenSsl.exception.message"));
		}

		if (encType == ENCRYPTED) {
			throw new PrivateKeyEncryptedException(res.getString("OpenSslIsEncrypted.exception.message"));
		}

		// Check if stream is PEM encoded
		PemInfo pemInfo = PemUtil.decode(new ByteArrayInputStream(streamContents));

		if (pemInfo != null) {
			// It is - get DER from PEM
			streamContents = pemInfo.getContent();
		}

		try {
			// Read OpenSSL DER structure
			ASN1InputStream asn1InputStream = new ASN1InputStream(streamContents);
			ASN1Primitive openSsl = asn1InputStream.readObject();
			asn1InputStream.close();

			if (openSsl instanceof ASN1Sequence) {
				ASN1Sequence seq = (ASN1Sequence) openSsl;

				if (seq.size() == 9) { // RSA private key

					BigInteger version = ((ASN1Integer) seq.getObjectAt(0)).getValue();
					BigInteger modulus = ((ASN1Integer) seq.getObjectAt(1)).getValue();
					BigInteger publicExponent = ((ASN1Integer) seq.getObjectAt(2)).getValue();
					BigInteger privateExponent = ((ASN1Integer) seq.getObjectAt(3)).getValue();
					BigInteger primeP = ((ASN1Integer) seq.getObjectAt(4)).getValue();
					BigInteger primeQ = ((ASN1Integer) seq.getObjectAt(5)).getValue();
					BigInteger primeExponentP = ((ASN1Integer) seq.getObjectAt(6)).getValue();
					BigInteger primeExponenetQ = ((ASN1Integer) seq.getObjectAt(7)).getValue();
					BigInteger crtCoefficient = ((ASN1Integer) seq.getObjectAt(8)).getValue();

					if (!version.equals(VERSION)) {
						throw new CryptoException(MessageFormat.format(
								res.getString("OpenSslVersionIncorrect.exception.message"), "" + VERSION.intValue(), ""
										+ version.intValue()));
					}

					RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec = new RSAPrivateCrtKeySpec(modulus, publicExponent,
							privateExponent, primeP, primeQ, primeExponentP, primeExponenetQ, crtCoefficient);

					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					return keyFactory.generatePrivate(rsaPrivateCrtKeySpec);
				} else if (seq.size() == 6) { // DSA private key

					BigInteger version = ((ASN1Integer) seq.getObjectAt(0)).getValue();
					BigInteger primeModulusP = ((ASN1Integer) seq.getObjectAt(1)).getValue();
					BigInteger primeQ = ((ASN1Integer) seq.getObjectAt(2)).getValue();
					BigInteger generatorG = ((ASN1Integer) seq.getObjectAt(3)).getValue();
					// publicExponentY not req for pvk: sequence.getObjectAt(4);
					BigInteger secretExponentX = ((ASN1Integer) seq.getObjectAt(5)).getValue();

					if (!version.equals(VERSION)) {
						throw new CryptoException(MessageFormat.format(
								res.getString("OpenSslVersionIncorrect.exception.message"), "" + VERSION.intValue(), ""
										+ version.intValue()));
					}

					DSAPrivateKeySpec dsaPrivateKeySpec = new DSAPrivateKeySpec(secretExponentX, primeModulusP, primeQ,
							generatorG);

					KeyFactory keyFactory = KeyFactory.getInstance("DSA");
					return keyFactory.generatePrivate(dsaPrivateKeySpec);
				} else if (seq.size() >= 2) { // EC private key (RFC 5915)

					org.bouncycastle.asn1.sec.ECPrivateKey pKey = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(seq);
					AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParameters());
					PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
					return new JcaPEMKeyConverter().getPrivateKey(privInfo);
				} else {
					throw new CryptoException(MessageFormat.format(
							res.getString("OpenSslSequenceIncorrectSize.exception.message"), "" + seq.size()));
				}
			} else {
				throw new CryptoException(res.getString("OpenSslSequenceNotFound.exception.message"));
			}
		} catch (Exception ex) {
			throw new CryptoException(res.getString("NoLoadOpenSslPrivateKey.exception.message"), ex);
		}
	}

	/**
	 * Load an encrypted OpenSSL private key from the specified stream. The
	 * encoding of the private key will be PEM.
	 *
	 * @param is
	 *            Stream load the encrypted private key from
	 * @param password
	 *            Password to decrypt
	 * @return The private key
	 * @throws PrivateKeyUnencryptedException
	 *             If private key is unencrypted
	 * @throws PrivateKeyPbeNotSupportedException
	 *             If private key PBE algorithm is not supported
	 * @throws CryptoException
	 *             Problem encountered while loading the private key
	 * @throws IOException
	 *             An I/O error occurred
	 */
	public static PrivateKey loadEncrypted(InputStream is, Password password) throws
	CryptoException, IOException {
		byte[] streamContents = ReadUtil.readFully(is);

		EncryptionType encType = getEncryptionType(new ByteArrayInputStream(streamContents));

		if (encType == null) {
			throw new CryptoException(res.getString("NotValidOpenSsl.exception.message"));
		}

		if (encType == UNENCRYPTED) {
			throw new PrivateKeyUnencryptedException(res.getString("OpenSslIsUnencrypted.exception.message"));
		}

		// OpenSSL must be encrypted and therefore must be PEM
		PemInfo pemInfo = PemUtil.decode(new ByteArrayInputStream(streamContents));

		byte[] encKey = pemInfo.getContent();

		PemAttributes attributes = pemInfo.getAttributes();
		String dekInfo = attributes.get(DEK_INFO_ATTR_NAME).getValue();

		// Split DEK-Info into encryption pbe algorithm and salt
		int separator = dekInfo.indexOf(',');

		if (separator == -1) {
			throw new CryptoException(MessageFormat.format("OpenSslDekInfoMalformed.exception.message", dekInfo));
		}

		String encAlg = dekInfo.substring(0, separator);
		String salt = dekInfo.substring(separator + 1);

		byte[] saltBytes = hexToBytes(salt);

		OpenSslPbeType pbeType = OpenSslPbeType.resolveDekInfo(encAlg);

		if (pbeType == null) {
			throw new PrivateKeyPbeNotSupportedException(encAlg, MessageFormat.format(
					res.getString("PrivateKeyWrappingAlgUnsupported.exception.message"), encAlg));
		}

		try {
			byte[] decryptKey = deriveKeyFromPassword(password, saltBytes, pbeType.keySize());

			// Create cipher - use all of the salt as the IV
			Cipher cipher = createCipher(pbeType.jceCipher(), decryptKey, saltBytes, DECRYPT_MODE);

			byte[] key = cipher.doFinal(encKey);

			return load(new ByteArrayInputStream(key));
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(MessageFormat.format("OpenSslDecryptionFailed.exception.message",
					pbeType.friendly()), ex);
		}
	}

	/**
	 * Detect if a OpenSSL private key is encrypted or not.
	 *
	 * @param is
	 *            Input stream containing OpenSSL private key
	 * @return Encryption type or null if not a valid OpenSSL private key
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public static EncryptionType getEncryptionType(InputStream is) throws IOException {
		byte[] openSsl = ReadUtil.readFully(is);

		// In PEM format?
		PemInfo pemInfo = PemUtil.decode(new ByteArrayInputStream(openSsl));

		if (pemInfo != null) {
			String pemType = pemInfo.getType();

			// PEM type of OpenSSL?
			if (OPENSSL_RSA_PVK_PEM_TYPE.equals(pemType) || OPENSSL_DSA_PVK_PEM_TYPE.equals(pemType)
					|| OPENSSL_EC_PVK_PEM_TYPE.equals(pemType)) {

				// Encrypted? It is if PEM contains appropriate header attributes/values
				PemAttributes pemAttributes = pemInfo.getAttributes();

				if ((pemAttributes != null) && (pemAttributes.get(PROC_TYPE_ATTR_NAME) != null)
						&& (pemAttributes.get(PROC_TYPE_ATTR_NAME).getValue().equals(PROC_TYPE_ATTR_VALUE))
						&& (pemAttributes.get(DEK_INFO_ATTR_NAME) != null)) {
					return ENCRYPTED;
				} else {
					return UNENCRYPTED;
				}
			}
		}

		// In ASN.1 format?
		try {
			// If OpenSSL will be a sequence of 9 (RSA) or 6 (DSA) integers or 2-4 mixed elements (EC)
			ASN1Primitive key = ASN1Primitive.fromByteArray(openSsl);

			if (key instanceof ASN1Sequence) {
				ASN1Sequence seq = (ASN1Sequence) key;

				// handle EC structure first (RFC 5915)
				//   ECPrivateKey ::= SEQUENCE {
				//	     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
				//	     privateKey     OCTET STRING,
				//	     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
				//	     publicKey  [1] BIT STRING OPTIONAL
				//	   }
				if ((seq.size() >= 2) && (seq.size() <= 4) && seq.getObjectAt(0) instanceof ASN1Integer) {
					BigInteger version = ((ASN1Integer) seq.getObjectAt(0)).getValue();
					if (version.equals(VERSION_EC)) {
						if (seq.getObjectAt(1) instanceof ASN1OctetString) {
							return UNENCRYPTED; // ASN.1 OpenSSL is always unencrypted
						} else {
							return null; // Not OpenSSL
						}
					}
				}

				for (int i = 0; i < seq.size(); i++) {
					if (!(seq.getObjectAt(i) instanceof ASN1Integer)) {
						return null; // Not OpenSSL
					}
				}

				if ((seq.size() == 9) || (seq.size() == 6)) {
					return UNENCRYPTED; // ASN.1 OpenSSL is always unencrypted
				}
			}
		} catch (IOException ex) {
			return null; // Not an OpenSSL file
		}

		return null; // Not an OpenSSL file
	}

	private static byte[] generateSalt(int size) {
		Random random = new Random();
		random.setSeed(Calendar.getInstance().getTimeInMillis());

		byte[] salt = new byte[size];

		random.nextBytes(salt);

		return salt;
	}

	private static byte[] deriveKeyFromPassword(Password password, byte[] salt, int keySize) throws CryptoException {
		// Derive a key of the required size from the supplied password and salt

		byte[] key = new byte[(keySize / 8)];

		byte[] passwordBytes = password.toByteArray();

		// Keep digesting password and salt until we have enough bytes for key
		MessageDigest messageDigest = DigestUtil.getMessageDigester(DigestType.MD5);

		byte[] result;
		int currentPos = 0;

		while (currentPos < key.length) {
			messageDigest.update(passwordBytes);

			// Only use the first 8 bytes of salt
			messageDigest.update(salt, 0, 8);

			result = messageDigest.digest();

			// How many more bytes do we need to complete key?
			int stillNeed = key.length - currentPos;

			// If this round gave us more than we need - trim it down
			if (result.length > stillNeed) {
				byte[] b = new byte[stillNeed];
				System.arraycopy(result, 0, b, 0, b.length);
				result = b;
			}

			// Add round's digest to key
			System.arraycopy(result, 0, key, currentPos, result.length);
			currentPos += result.length;

			if (currentPos < key.length) {
				// Next round starts with a hash this round's hash
				messageDigest.reset();
				messageDigest.update(result);
			}
		}

		return key;
	}

	private static byte[] hexToBytes(String hex) {
		byte[] b = new byte[hex.length() / 2];
		for (int i = 0; i < b.length; i++) {
			String hexByte = hex.substring(2 * i, 2 * (i + 1));
			b[i] = (byte) Integer.parseInt(hexByte, 16);
		}
		return b;
	}

	private static String bytesToHex(byte[] bytes) {
		int expectedHexLength = (bytes.length * 2);

		String hex = new BigInteger(1, bytes).toString(16).toUpperCase();

		int leadingZeros = expectedHexLength - hex.length();

		for (int i = 0; i < leadingZeros; i++) {
			hex = "0" + hex; // Use leading zeros to ensure correct string
			// length
		}

		return hex;
	}

	private static Cipher createCipher(String transformation, byte[] key, byte[] iv, int operation)
			throws CryptoException {
		SecretKey secretKey = new SecretKeySpec(key, transformation);
		IvParameterSpec ivParams = new IvParameterSpec(iv);

		try {
			Cipher cipher = Cipher.getInstance(transformation, "BC");
			cipher.init(operation, secretKey, ivParams);
			return cipher;
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(MessageFormat.format("OpenSslCreateCipherFailed.exception.message",
					transformation), ex);
		}
	}
}
