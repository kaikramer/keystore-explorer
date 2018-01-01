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

import static org.kse.crypto.privatekey.EncryptionType.ENCRYPTED;
import static org.kse.crypto.privatekey.EncryptionType.UNENCRYPTED;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.text.MessageFormat;
import java.util.Calendar;
import java.util.Random;
import java.util.ResourceBundle;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.utilities.io.ReadUtil;
import org.kse.utilities.io.UnsignedUtil;

// @formatter:off
/**
 * Provides utility methods relating to Microsoft PVK encoded RSA and DSS (DSA)
 * private keys.
 *
 * <pre>
 * PVK format for RSA and DSS private keys:
 *
 *     DWORD magic     = PVK_MAGIC_NUMBER
 *     DWORD reserved  = PVK_RESERVED
 *     DWORD keytype   = PVK_KEY_EXCHANGE | PVK_KEY_SIGNATURE
 *     DWORD encrypted = PVK_UNENCRYPTED | PVK_ENCRYPTED
 *     DWORD saltlen   = UNENCRYPTED_SALT_LENGTH | ENCRYPTED_SALT_LENGTH
 *     DWORD keylen
 *     BYTE  salt[saltlen]
 *     BLOBHEADER blobheader
 *     PublicKeyBlob publicKeyBlob
 *
 *     BLOBHEADER:
 *
 *         BYTE bType      = PRIVATE_KEY_BLOB
 *         BYTE bVersion   = CUR_BLOB_VERSION
 *         WORD reserved   = BLOB_RESERVED
 *         ALG_ID aiKeyAlg = CALG_RSA_SIGN | CALG_RSA_KEYX | CALG_DSS_SIGN
 *
 *     RSA PublicKeyBlob:
 *
 *         RSAPUBKEY rsapubkey
 *         BYTE modulus[rsapubkey.bitlen/8]
 *         BYTE prime1[rsapubkey.bitlen/16]
 *         BYTE prime2[rsapubkey.bitlen/16]
 *         BYTE exponent1[rsapubkey.bitlen/16]
 *         BYTE exponent2[rsapubkey.bitlen/16]
 *         BYTE coefficient[rsapubkey.bitlen/16]
 *         BYTE privateExponent[rsapubkey.bitlen/8]
 *
 *         RSAPUBKEY:
 *
 *             DWORD magic = RSA_PRIV_MAGIC
 *             DWORD bitlen
 *             DWORD pubexp
 *
 *     DSS PublicKeyBlob:
 *
 *         DSSPUBKEY dsspubkey
 *         BYTE p[dsspubkey.bitlen/8]
 *         BYTE q[20]
 *         BYTE g[dsspubkey.bitlen/8]
 *         BYTE x[20]
 *         DSSSEED seedstruct
 *
 *         DSSPUBKEY:
 *
 *             DWORD magic = DSA_PRIV_MAGIC
 *             DWORD bitlen
 *
 *         DSSSEED:
 *
 *             DWORD counter
 *             BYTE seed[20]
 * </pre>
 *
 */
// @formatter:on
public class MsPvkUtil {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/privatekey/resources");

	// Magic number field value
	private static final long PVK_MAGIC_NUMBER = 0xb0b5f11eL;

	// Reserved field value
	private static final int PVK_RESERVED = 0;

	// Key exchange value for key type
	public static final int PVK_KEY_EXCHANGE = 1;

	// Signature value for key type
	public static final int PVK_KEY_SIGNATURE = 2;

	// Unencrypted value for encrypted field
	private static final long PVK_UNENCRYPTED = 0;

	// Encrypted value for unencrypted field
	private static final int PVK_ENCRYPTED = 1;

	// Salt length for unencrypted PVK
	private static final long UNENCRYPTED_SALT_LENGTH = 0;

	// Salt length for encrypted PVK
	private static final int ENCRYPTED_SALT_LENGTH = 0x10;

	// PVK BLOB type field value
	private static final short PRIVATE_KEY_BLOB = 7;

	// PVK BLOB version field value
	private static final short CUR_BLOB_VERSION = 2;

	// PVK BLOB reserved field value
	private static final int BLOB_RESERVED = 0;

	// PVK key algortihm id field value for RSA signature private key
	private static final int CALG_RSA_SIGN = 0x2400;

	// PVK key algortihm id field value for RSA exchange private key
	private static final int CALG_RSA_KEYX = 0xa400;

	// PVK key algorithm id field value for DSA signature private key
	private static final int CALG_DSS_SIGN = 0x2200;

	// RSA private key magic number
	private static final int RSA_PRIV_MAGIC = 0x32415352;

	// DSS private key magic number
	private static final int DSS_PRIV_MAGIC = 0x32535344;

	// Length of a private key blob header in bytes
	private static final int BLOB_HEADER_LENGTH = 8;

	/*
	 * Length of PVK read buffer used when creating PVK encoding This should be
	 * large enough as even an encrypted 4096 RSA PVK only requires 2364 bytes
	 */
	private static final int PVK_BUFFER_LENGTH = 8192;

	private MsPvkUtil() {
	}

	/**
	 * Load an unencrypted PVK private key from the stream.
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
	public static PrivateKey load(InputStream is) throws IOException, CryptoException {
		byte[] pvk = ReadUtil.readFully(is);

		// Wrap in a byte buffer set up to read little endian
		ByteBuffer bb = ByteBuffer.wrap(pvk);
		bb.order(ByteOrder.LITTLE_ENDIAN);

		// Read and validate the reserved, magic number and key type fields - only returns the latter
		long keyType = readReservedMagicKeyType(bb);

		// Read and validate encrypted field
		long encrypted = UnsignedUtil.getInt(bb);

		if (encrypted != PVK_UNENCRYPTED) {
			throw new PrivateKeyEncryptedException(MessageFormat.format(
					res.getString("MsPvkIsEncrypted.exception.message"), Long.toHexString(encrypted),
					Long.toHexString(PVK_UNENCRYPTED)));
		}

		// Read and validate salt length field
		long saltLength = UnsignedUtil.getInt(bb);

		if (saltLength != UNENCRYPTED_SALT_LENGTH) // Specific length (0) for unencrypted PVK
		{
			throw new CryptoException(MessageFormat.format(
					res.getString("InvalidMsPvkSaltLengthField.exception.message"), Long.toHexString(saltLength),
					Long.toHexString(UNENCRYPTED_SALT_LENGTH)));
		}

		// Read key length
		long keyLength = UnsignedUtil.getInt(bb);

		// Read private key blob header
		readPrivateKeyBlobHeader(bb, keyType);

		// Read all remaining bytes as the private key blob
		byte[] privateKeyBlob = new byte[bb.remaining()];
		bb.get(privateKeyBlob);

		// Validate key length - should be length of key blob plus blob header
		if (keyLength != (privateKeyBlob.length + BLOB_HEADER_LENGTH)) {
			throw new CryptoException(MessageFormat.format(
					res.getString("InvalidMsPvkKeyLengthField.exception.message"), Long.toHexString(keyLength),
					Long.toHexString(privateKeyBlob.length + BLOB_HEADER_LENGTH)));
		}

		return blobToPrivateKey(privateKeyBlob);
	}

	/**
	 * Load an encrypted PVK private key from the specified stream.
	 *
	 * @param is
	 *            Stream load the encrypted private key from
	 * @param password
	 *            Password to decrypt
	 * @return The private key
	 * @throws PrivateKeyUnencryptedException
	 *             If private key is unencrypted
	 * @throws CryptoException
	 *             Problem encountered while loading the private key
	 * @throws IOException
	 *             An I/O error occurred
	 */
	public static PrivateKey loadEncrypted(InputStream is, Password password) throws IOException,
	CryptoException {
		try {
			byte[] pvk = ReadUtil.readFully(is);

			// Wrap in a byte buffer set up to read little endian
			ByteBuffer bb = ByteBuffer.wrap(pvk);
			bb.order(ByteOrder.LITTLE_ENDIAN);

			// Read and validate the reserved, magic number and key type fields - only returns the latter
			long keyType = readReservedMagicKeyType(bb);

			// Read and validate encrypted field
			long encrypted = UnsignedUtil.getInt(bb);

			if (encrypted != PVK_ENCRYPTED) {
				throw new PrivateKeyUnencryptedException(MessageFormat.format(
						res.getString("MsPvkIsUnencrypted.exception.message"), Long.toHexString(encrypted),
						Long.toHexString(PVK_ENCRYPTED)));
			}

			// Read and validate salt length field
			long saltLength = UnsignedUtil.getInt(bb);

			if (saltLength != ENCRYPTED_SALT_LENGTH) { // Specific length for encrypted PVK
				throw new CryptoException(MessageFormat.format(
						res.getString("InvalidMsPvkSaltLengthField.exception.message"), Long.toHexString(saltLength),
						Long.toHexString(ENCRYPTED_SALT_LENGTH)));
			}

			// Read key length
			long keyLength = UnsignedUtil.getInt(bb);

			// Create decryption keys
			byte[] strongKey = new byte[16]; // Strong version
			byte[] weakKey = new byte[16]; // Weak version

			// Read Salt
			byte salt[] = new byte[(int) saltLength];
			bb.get(salt);

			// Concatenate salt and password and derive key using SHA-1
			MessageDigest messagedigest = MessageDigest.getInstance("SHA1");

			byte[] passwordBytes = new String(password.toCharArray()).getBytes();
			byte[] saltAndPassword = new byte[salt.length + passwordBytes.length];

			System.arraycopy(salt, 0, saltAndPassword, 0, salt.length);
			System.arraycopy(passwordBytes, 0, saltAndPassword, salt.length, passwordBytes.length);

			byte[] key = messagedigest.digest(saltAndPassword);

			// Create strong key - first 16 bytes of key
			System.arraycopy(key, 0, strongKey, 0, 16);

			// Create weak key - first 5 bytes of key followed by 11 zero bytes
			System.arraycopy(key, 0, weakKey, 0, 5);

			for (int i = 5; i < 16; i++) {
				weakKey[i] = 0;
			}

			// Read private key blob header
			readPrivateKeyBlobHeader(bb, keyType);

			// Read all remaining bytes - the encrypted key
			byte[] encryptedPrivateKeyBlob = new byte[bb.remaining()];
			bb.get(encryptedPrivateKeyBlob);

			// Validate key length - should be length of encrypted key blob plus blob header
			if (keyLength != (encryptedPrivateKeyBlob.length + BLOB_HEADER_LENGTH)) {
				throw new CryptoException(MessageFormat.format(
						res.getString("InvalidMsPvkKeyLengthField.exception.message"), Long.toHexString(keyLength),
						Long.toHexString(encryptedPrivateKeyBlob.length + BLOB_HEADER_LENGTH)));
			}

			// Decrypt key using RC4 with strong key
			byte[] decryptedPrivateKeyBlob = decryptPrivateKeyBlob(encryptedPrivateKeyBlob, strongKey);

			// Test for success
			if (decryptedPrivateKeyBlob == null) {
				// Failed - now try weak key
				decryptedPrivateKeyBlob = decryptPrivateKeyBlob(encryptedPrivateKeyBlob, weakKey);

				if (decryptedPrivateKeyBlob == null) {
					// Failed - could not decrypt - password is most likely incorrect
					throw new CryptoException(res.getString("NoDecryptMsPvkCheckPassword.exception.message"));
				}
			}

			return blobToPrivateKey(decryptedPrivateKeyBlob);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoLoadMsPvk.exception.message"), ex);
		}
	}

	/**
	 * PVK encode an RSA private key.
	 *
	 * @param privateKey
	 *            The private key
	 * @param keyType
	 *            PVK_KEY_EXCHANGE or PVK_KEY_SIGNATURE
	 * @return The encoding
	 * @throws CryptoException
	 *             Problem encountered while getting the encoded private key
	 */
	public static byte[] get(RSAPrivateCrtKey privateKey, int keyType) throws CryptoException {
		return getInternal(privateKey, keyType);
	}

	/**
	 * PVK encode a DSA private key.
	 *
	 * @param privateKey
	 *            The private key
	 * @return The encoding
	 * @throws CryptoException
	 *             Problem encountered while getting the encoded private key
	 */
	public static byte[] get(DSAPrivateKey privateKey) throws CryptoException {
		return getInternal(privateKey, PVK_KEY_SIGNATURE);
	}

	/**
	 * Detect if a Microsoft PVK private key is encrypted or not.
	 *
	 * @param is
	 *            Input stream containing Microsoft PVK private key
	 * @return Encryption type or null if not a valid Microsoft PVK private key
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public static EncryptionType getEncryptionType(InputStream is) throws IOException {
		byte[] pvk = ReadUtil.readFully(is);

		// Wrap in a byte buffer set up to read little endian
		ByteBuffer bb = ByteBuffer.wrap(pvk);
		bb.order(ByteOrder.LITTLE_ENDIAN);

		// Read and validate magic number field
		long magic = UnsignedUtil.getInt(bb);

		if (magic != PVK_MAGIC_NUMBER) {
			return null;
		}

		// Read and validate reserved field
		long reserved = UnsignedUtil.getInt(bb);

		if (reserved != PVK_RESERVED) {
			return null;
		}

		// Read and validate key type field
		long keyType = UnsignedUtil.getInt(bb);

		if ((keyType != PVK_KEY_EXCHANGE) && (keyType != PVK_KEY_SIGNATURE)) {
			return null;
		}

		// Read and validate encrypted field
		long encrypted = UnsignedUtil.getInt(bb);

		if (encrypted == PVK_ENCRYPTED) {
			return ENCRYPTED;
		} else if (encrypted == PVK_UNENCRYPTED) {
			return UNENCRYPTED;
		}

		return null;
	}

	private static byte[] getInternal(PrivateKey privateKey, int keyType) throws CryptoException {
		// PVK encode a private key unencrypted

		try {
			// Write PVK to a byte buffer set up to write little endian
			ByteBuffer bb = ByteBuffer.wrap(new byte[PVK_BUFFER_LENGTH]);
			bb.order(ByteOrder.LITTLE_ENDIAN);

			// Write magic number, reserved and and key type fields
			writeReservedMagicKeyType(bb, keyType);

			// Get unencrypted private key blob
			byte[] privateKeyBlob = null;

			if (privateKey instanceof RSAPrivateCrtKey) {
				privateKeyBlob = rsaPrivateKeyToBlob((RSAPrivateCrtKey) privateKey);
			} else {
				privateKeyBlob = dsaPrivateKeyToBlob((DSAPrivateKey) privateKey);
			}

			// Write type field - unencrypted
			UnsignedUtil.putInt(bb, PVK_UNENCRYPTED);

			// Write salt length - unencrypted so no salt, length = 0
			UnsignedUtil.putInt(bb, UNENCRYPTED_SALT_LENGTH);

			// Write key length field - length of the blob plus length of blob header
			long keyLength = privateKeyBlob.length + BLOB_HEADER_LENGTH;
			UnsignedUtil.putInt(bb, keyLength);

			// Write private key blob header
			writePrivateKeyBlobHeader(bb, keyType, privateKey);

			// Write private key blob
			bb.put(privateKeyBlob);

			byte[] pvk = getBufferBytes(bb);

			return pvk;
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoGetMsPvk.exception.message"), ex);
		}
	}

	/**
	 * PVK encode and encrypt an RSA private key.
	 *
	 * @param privateKey
	 *            The RSA private key
	 * @param keyType
	 *            PVK_KEY_EXCHANGE or PVK_KEY_SIGNATURE
	 * @param password
	 *            Encryption password
	 * @param strong
	 *            Use strong key for encryption?
	 * @return The encoding
	 * @throws CryptoException
	 *             Problem encountered while getting the encoded private key
	 */
	public static byte[] getEncrypted(RSAPrivateCrtKey privateKey, int keyType, Password password, boolean strong)
			throws CryptoException {
		return getEncryptedInternal(privateKey, keyType, password, strong);
	}

	/**
	 * PVK encode and encrypt a DSA private key.
	 *
	 * @param privateKey
	 *            The DSA private key
	 * @param password
	 *            Encryption password
	 * @param strong
	 *            Use strong key for encryption?
	 * @return The encoding
	 * @throws CryptoException
	 *             Problem encountered while getting the encoded private key
	 */
	public static byte[] getEncrypted(DSAPrivateKey privateKey, Password password, boolean strong)
			throws CryptoException {
		return getEncryptedInternal(privateKey, PVK_KEY_SIGNATURE, password, strong);
	}

	private static byte[] getEncryptedInternal(PrivateKey privateKey, int keyType, Password password, boolean strong)
			throws CryptoException {
		// PVK encode a private key unencrypted

		try {
			// Write PVK to a byte buffer set up to write little endian
			ByteBuffer bb = ByteBuffer.wrap(new byte[PVK_BUFFER_LENGTH]);
			bb.order(ByteOrder.LITTLE_ENDIAN);

			// Write magic number, reserved and and key type fields
			writeReservedMagicKeyType(bb, keyType);

			// Get password as bytes
			byte[] passwordBytes = new String(password.toCharArray()).getBytes();

			// Generate salt for encryption
			byte[] salt = generate16ByteSalt();

			// Concatenate the salt and password
			byte[] saltAndPassword = new byte[salt.length + passwordBytes.length];
			System.arraycopy(salt, 0, saltAndPassword, 0, salt.length);
			System.arraycopy(passwordBytes, 0, saltAndPassword, salt.length, passwordBytes.length);

			// Digest the salt and password to create the encryption key
			MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
			byte[] key = messageDigest.digest(saltAndPassword);

			// Get private key blob
			byte[] privateKeyBlob = null;

			if (privateKey instanceof RSAPrivateCrtKey) {
				privateKeyBlob = rsaPrivateKeyToBlob((RSAPrivateCrtKey) privateKey);
			} else {
				privateKeyBlob = dsaPrivateKeyToBlob((DSAPrivateKey) privateKey);
			}

			// Encrypt private key blob
			byte[] encryptedPrivateKeyBlob = null;

			if (strong) {
				// Strong version uses all 16 bytes of the key
				byte[] strongKey = new byte[16];
				System.arraycopy(key, 0, strongKey, 0, strongKey.length);
				encryptedPrivateKeyBlob = encryptPrivateKeyBlob(privateKeyBlob, strongKey);
			} else {
				// The weak version uses only 5 bytes of the key followed by 11 zero bytes
				byte[] weakKey = new byte[16];
				System.arraycopy(key, 0, weakKey, 0, 5);
				for (int i = 5; i < weakKey.length; i++) {
					weakKey[i] = 0;
				}

				encryptedPrivateKeyBlob = encryptPrivateKeyBlob(privateKeyBlob, weakKey);
			}

			// Write type field - encrypted
			UnsignedUtil.putInt(bb, PVK_ENCRYPTED);

			// Write salt length field
			UnsignedUtil.putInt(bb, salt.length);

			// Write key length field - length of the blob plus length blob header
			int keyLength = encryptedPrivateKeyBlob.length + BLOB_HEADER_LENGTH;
			UnsignedUtil.putInt(bb, keyLength);

			// Write salt
			bb.put(salt);

			// Write private key blob header
			writePrivateKeyBlobHeader(bb, keyType, privateKey);

			// Write blob
			bb.put(encryptedPrivateKeyBlob);

			byte[] encryptedPvk = getBufferBytes(bb);

			return encryptedPvk;
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoGetMsPvk.exception.message"), ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(res.getString("NoGetMsPvk.exception.message"), ex);
		}
	}

	private static void writeReservedMagicKeyType(ByteBuffer bb, long keyType) throws IOException, CryptoException {
		// Write the PVK fields: reserved, magic and key type

		UnsignedUtil.putInt(bb, PVK_MAGIC_NUMBER);

		UnsignedUtil.putInt(bb, PVK_RESERVED);

		if ((keyType != PVK_KEY_EXCHANGE) && (keyType != PVK_KEY_SIGNATURE)) {
			throw new CryptoException(MessageFormat.format(res.getString("InvalidMsPvkKeyTypeField.exception.message"),
					Long.toHexString(keyType), Long.toHexString(PVK_KEY_EXCHANGE), Long.toHexString(PVK_KEY_SIGNATURE)));
		}

		UnsignedUtil.putInt(bb, keyType);
	}

	private static long readReservedMagicKeyType(ByteBuffer bb) throws IOException, CryptoException {
		/*
		 * Read and validate the starting PVK fields: reserved, magic and key
		 * type. While all three fields are validated only the key type is of
		 * further interest and is therefore returned
		 */

		long magic = UnsignedUtil.getInt(bb);

		if (magic != PVK_MAGIC_NUMBER) {
			throw new CryptoException(MessageFormat.format(res.getString("InvalidMsPvkMagicField.exception.message"),
					Long.toHexString(magic), Long.toHexString(PVK_MAGIC_NUMBER)));
		}

		long reserved = UnsignedUtil.getInt(bb);

		if (reserved != PVK_RESERVED) {
			throw new CryptoException(MessageFormat.format(
					res.getString("InvalidMsPvkReservedField.exception.message"), Long.toHexString(reserved),
					Long.toHexString(PVK_RESERVED)));
		}

		long keyType = UnsignedUtil.getInt(bb);

		if ((keyType != PVK_KEY_EXCHANGE) && (keyType != PVK_KEY_SIGNATURE)) {
			throw new CryptoException(MessageFormat.format(res.getString("InvalidMsPvkKeyTypeField.exception.message"),
					Long.toHexString(keyType), Long.toHexString(PVK_KEY_EXCHANGE), Long.toHexString(PVK_KEY_SIGNATURE)));
		}

		return keyType;
	}

	private static void writePrivateKeyBlobHeader(ByteBuffer bb, long keyType, PrivateKey privateKey)
			throws IOException {
		// Write Key blob type - private key
		UnsignedUtil.putByte(bb, PRIVATE_KEY_BLOB);

		// Write Blob version
		UnsignedUtil.putByte(bb, CUR_BLOB_VERSION);

		// Write Reserved value
		UnsignedUtil.putShort(bb, BLOB_RESERVED);

		// Write Algorithm ID - differs depending on key type and key pair type
		if (keyType == PVK_KEY_SIGNATURE) {
			if (privateKey instanceof RSAPrivateCrtKey) {
				UnsignedUtil.putInt(bb, CALG_RSA_SIGN); // RSA signature
			} else {
				UnsignedUtil.putInt(bb, CALG_DSS_SIGN); // DSA signature
			}
		} else {
			UnsignedUtil.putInt(bb, CALG_RSA_KEYX); // Key exchange - RSA only
		}
	}

	private static void readPrivateKeyBlobHeader(ByteBuffer bb, long keyType) throws IOException, CryptoException {
		// Read and validate BLOB header type field
		int blobType = UnsignedUtil.getByte(bb);

		if (blobType != PRIVATE_KEY_BLOB) {
			throw new CryptoException(MessageFormat.format(
					res.getString("InvalidBlobHeaderTypeField.exception.message"), Integer.toHexString(blobType),
					Integer.toHexString(PRIVATE_KEY_BLOB)));
		}

		// Read and validate BLOB header version field
		short blobVersion = UnsignedUtil.getByte(bb);

		if (blobVersion != CUR_BLOB_VERSION) {
			throw new CryptoException(MessageFormat.format(
					res.getString("InvalidBlobHeaderVersionField.exception.message"), Integer.toHexString(blobVersion),
					Integer.toHexString(CUR_BLOB_VERSION)));
		}

		// Read and validate BLOB header reserved field
		int blobReserved = UnsignedUtil.getShort(bb);

		if (blobReserved != BLOB_RESERVED) {
			throw new CryptoException(MessageFormat.format(
					res.getString("InvalidBlobHeaderReservedField.exception.message"),
					Integer.toHexString(blobReserved), Integer.toHexString(BLOB_RESERVED)));
		}

		// Read and validate BLOB header algorithm ID

		long keyAlgId = UnsignedUtil.getInt(bb);

		// Only accept RSA or DSS - algorithm ID must match key type
		if (keyType == PVK_KEY_SIGNATURE) {
			// RSA or DSS for signature
			if ((keyAlgId != CALG_RSA_SIGN) && (keyAlgId != CALG_DSS_SIGN)) {
				throw new CryptoException(MessageFormat.format(
						res.getString("InvalidBlobHeaderKeyAlgIdField.exception.message"), Long.toHexString(keyAlgId),
						Long.toHexString(CALG_RSA_SIGN), Long.toHexString(CALG_DSS_SIGN)));
			}
		} else {
			// RSA for key exchange - DSS cannot be used for key exchange
			if (keyAlgId != CALG_RSA_KEYX) {
				throw new CryptoException(MessageFormat.format(
						res.getString("InvalidBlobHeaderKeyAlgIdField.exception.message"), Long.toHexString(keyAlgId),
						Long.toHexString(CALG_RSA_KEYX)));
			}
		}
	}

	private static PrivateKey blobToPrivateKey(byte[] privateKeyBlob) throws CryptoException {
		if ((privateKeyBlob[0] == 82) && // R
				(privateKeyBlob[1] == 83) && // S
				(privateKeyBlob[2] == 65) && // A
				(privateKeyBlob[3] == 50)) // 2
		{
			return blobToRsaPrivateKey(privateKeyBlob);
		} else {
			return blobToDsaPrivateKey(privateKeyBlob);
		}
	}

	private static RSAPrivateCrtKey blobToRsaPrivateKey(byte[] rsaPrivateKeyBlob) throws CryptoException {
		try {
			ByteBuffer bb = ByteBuffer.wrap(rsaPrivateKeyBlob);
			bb.order(ByteOrder.LITTLE_ENDIAN);

			// Get each blob field

			long magic = UnsignedUtil.getInt(bb); // rsapubkey.magic

			// Check magic field is valid
			if (magic != RSA_PRIV_MAGIC) {
				throw new CryptoException(MessageFormat.format(res.getString("InvalidRsaMagicField.exception.message"),
						Long.toHexString(magic), Long.toHexString(RSA_PRIV_MAGIC)));
			}

			long bitLength = UnsignedUtil.getInt(bb); // rsapubkey.bitlen

			// Byte lengths divisions may have remainders to take account for if not factors of 16 and/or 8
			int add8 = 0;
			if ((bitLength % 8) != 0) {
				add8++;
			}

			int add16 = 0;
			if ((bitLength % 16) != 0) {
				add16++;
			}

			BigInteger publicExponent = new BigInteger(Long.toString(UnsignedUtil.getInt(bb))); // rsapubkey.pubexp

			BigInteger modulus = readBigInteger(bb, (int) (bitLength / 8) + add8); // modulus
			BigInteger prime1 = readBigInteger(bb, (int) (bitLength / 16) + add16); // prime 1
			BigInteger prime2 = readBigInteger(bb, (int) (bitLength / 16) + add16); // prime 2
			BigInteger exponent1 = readBigInteger(bb, (int) (bitLength / 16) + add16); // exponent1
			BigInteger exponent2 = readBigInteger(bb, (int) (bitLength / 16) + add16); // exponent2
			BigInteger coefficient = readBigInteger(bb, (int) (bitLength / 16) + add16); // coefficient
			BigInteger privateExponent = readBigInteger(bb, (int) (bitLength / 8) + add8); // privateExponent

			RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec = new RSAPrivateCrtKeySpec(modulus, publicExponent,
					privateExponent, prime1, prime2, exponent1, exponent2, coefficient);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return (RSAPrivateCrtKey) keyFactory.generatePrivate(rsaPrivateCrtKeySpec);
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoConvertBlobToRsaKey.exception.message"), ex);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoConvertBlobToRsaKey.exception.message"), ex);
		}
	}

	private static DSAPrivateKey blobToDsaPrivateKey(byte[] dsaPrivateKeyBlob) throws CryptoException {
		try {
			ByteBuffer bb = ByteBuffer.wrap(dsaPrivateKeyBlob);
			bb.order(ByteOrder.LITTLE_ENDIAN);

			// Get each blob field

			long magic = UnsignedUtil.getInt(bb); // dsspubkey.magic

			// Check magic field is valid
			if (magic != DSS_PRIV_MAGIC) {
				throw new CryptoException(MessageFormat.format(res.getString("InvalidDsaMagicField.exception.message"),
						Long.toHexString(magic), Long.toHexString(DSS_PRIV_MAGIC)));
			}

			long bitLength = UnsignedUtil.getInt(bb); // dsspubkey.bitlen

			BigInteger p = readBigInteger(bb, (int) (bitLength / 8)); // modulus
			BigInteger q = readBigInteger(bb, 20); // prime
			BigInteger g = readBigInteger(bb, (int) (bitLength / 8)); // generator
			BigInteger x = readBigInteger(bb, 20); // secret exponent

			// Ignore 24 bytes of dssseed (only applicable to public keys)
			for (int i = 0; i < 24; i++) {
				bb.get();
			}

			DSAPrivateKeySpec dsaPrivateKeySpec = new DSAPrivateKeySpec(x, p, q, g);

			KeyFactory keyFactory = KeyFactory.getInstance("DSA");
			return (DSAPrivateKey) keyFactory.generatePrivate(dsaPrivateKeySpec);
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoConvertBlobToDsaKey.exception.message"), ex);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoConvertBlobToDsaKey.exception.message"), ex);
		}
	}

	private static byte[] rsaPrivateKeyToBlob(RSAPrivateCrtKey rsaPrivCrtKey) throws CryptoException {
		try {
			ByteBuffer bb = ByteBuffer.wrap(new byte[4096]); // 2316 sufficient for a 4096 bit RSA key
			bb.order(ByteOrder.LITTLE_ENDIAN);

			// Write out the blob fields

			UnsignedUtil.putInt(bb, RSA_PRIV_MAGIC); // rsapubkey.magic

			BigInteger modulus = rsaPrivCrtKey.getModulus();
			int bitLength = modulus.bitLength();
			UnsignedUtil.putInt(bb, bitLength); // rsapubkey.bitlen

			BigInteger publicExponent = rsaPrivCrtKey.getPublicExponent();
			UnsignedUtil.putInt(bb, (int) publicExponent.longValue()); // rsapubkey.pubexp

			/*
			 * Byte lengths divisions may have remainders to take account for if
			 * not factors of 16 and/or 8
			 */
			int add8 = 0;
			if ((bitLength % 8) != 0) {
				add8++;
			}

			int add16 = 0;
			if ((bitLength % 16) != 0) {
				add16++;
			}

			writeBigInteger(bb, modulus, (bitLength / 8) + add8); // modulus
			writeBigInteger(bb, rsaPrivCrtKey.getPrimeP(), (bitLength / 16) + add16); // prime1
			writeBigInteger(bb, rsaPrivCrtKey.getPrimeQ(), (bitLength / 16) + add16); // prime2
			writeBigInteger(bb, rsaPrivCrtKey.getPrimeExponentP(), (bitLength / 16) + add16); // exponent1
			writeBigInteger(bb, rsaPrivCrtKey.getPrimeExponentQ(), (bitLength / 16) + add16); // exponent2
			writeBigInteger(bb, rsaPrivCrtKey.getCrtCoefficient(), (bitLength / 16) + add16); // coefficient
			writeBigInteger(bb, rsaPrivCrtKey.getPrivateExponent(), (bitLength / 8) + add8); // privateExponent

			return getBufferBytes(bb);
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoConvertKeyToBlob.exception.message"), ex);
		}
	}

	private static byte[] dsaPrivateKeyToBlob(DSAPrivateKey dsaPrivKey) throws CryptoException {
		try {
			DSAParams dsaParams = dsaPrivKey.getParams();

			ByteBuffer bb = ByteBuffer.wrap(new byte[512]); // 328 sufficient for a 1024 bit DSA key
			bb.order(ByteOrder.LITTLE_ENDIAN);

			// Write out the blob fields

			UnsignedUtil.putInt(bb, DSS_PRIV_MAGIC); // dsspubkey.magic

			BigInteger prime = dsaParams.getP();
			int bitLength = prime.toString(2).length();
			UnsignedUtil.putInt(bb, bitLength); // dsspubkey.bitlen

			/*
			 * Unlike RSA there are no bit length remainders (ie DSA bit length
			 * always divisible by 8 as they are multiples of 64)
			 */

			writeBigInteger(bb, dsaParams.getP(), (bitLength / 8)); // modulus
			writeBigInteger(bb, dsaParams.getQ(), 20); // prime
			writeBigInteger(bb, dsaParams.getG(), (bitLength / 8)); // generator
			writeBigInteger(bb, dsaPrivKey.getX(), 20); // secret exponent

			UnsignedUtil.putInt(bb, 0xffffffff); // dssseed.counter - none, fill 0xff

			for (int i = 0; i < 20; i++) // dssseed.seed - none, fill 0xff
			{
				bb.put((byte) 0xff);
			}

			return getBufferBytes(bb);
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoConvertKeyToBlob.exception.message"), ex);
		}
	}

	private static byte[] decryptPrivateKeyBlob(byte[] encryptedPvk, byte[] rc4Key) throws CryptoException {
		// Decrypt encrypted private key blob using RC4

		try {
			SecretKeySpec rc4KeySpec = new SecretKeySpec(rc4Key, "RC4");
			Cipher rc42 = Cipher.getInstance("RC4");
			rc42.init(Cipher.DECRYPT_MODE, rc4KeySpec);
			byte[] decryptedKeyBlob = rc42.doFinal(encryptedPvk);

			// Test if key decryption was successful

			// First four bytes will be "RSA2" if successful for an RSA private key
			if ((decryptedKeyBlob[0] == 82) && // R
					(decryptedKeyBlob[1] == 83) && // S
					(decryptedKeyBlob[2] == 65) && // A
					(decryptedKeyBlob[3] == 50)) // 2
			{
				return decryptedKeyBlob;
			}
			// First four bytes will be "DSS2" if successful for a DSA private key
			else if ((decryptedKeyBlob[0] == 68) && // D
					(decryptedKeyBlob[1] == 83) && // S
					(decryptedKeyBlob[2] == 83) && // S
					(decryptedKeyBlob[3] == 50)) // 2
			{
				return decryptedKeyBlob;
			} else {
				return null;
			}
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("PrivateKeyBlobRc4DecryptionFailed.exception.message"), ex);
		}
	}

	private static byte[] encryptPrivateKeyBlob(byte[] privateKeyBlob, byte[] rc4Key) throws CryptoException {
		// Encrypt private key blob using RC4

		try {
			SecretKeySpec rc4KeySpec = new SecretKeySpec(rc4Key, "RC4");
			Cipher rc42 = Cipher.getInstance("RC4");
			rc42.init(Cipher.ENCRYPT_MODE, rc4KeySpec);

			return rc42.doFinal(privateKeyBlob);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("PrivateKeyBlobRc4EncryptionFailed.exception.message"), ex);
		}
	}

	private static byte[] generate16ByteSalt() {
		// Generate 16-byte salt for use with RC4

		Random random = new Random();
		random.setSeed(Calendar.getInstance().getTimeInMillis());

		byte[] salt = new byte[16];
		random.nextBytes(salt);

		return salt;
	}

	private static byte[] getBufferBytes(ByteBuffer bb) {
		byte[] buffer = bb.array();

		// Read all of the byte's in the backing array to the extent writing
		// took place
		byte[] written = new byte[bb.position()];

		System.arraycopy(buffer, 0, written, 0, written.length);

		return written;
	}

	private static BigInteger readBigInteger(ByteBuffer bb, int length) throws IOException {
		// Read a big integer from a little endian source

		// Read the required number of bytes
		byte[] bigIntBytes = new byte[length];
		bb.get(bigIntBytes);

		/*
		 * The byte buffer's byte order does not apply for get() so reverse to
		 * convert from little to big endian
		 */
		reverseBytes(bigIntBytes);

		// Construct and return the big integer
		BigInteger bigInt = new BigInteger(1, bigIntBytes);

		return bigInt;
	}

	private static void writeBigInteger(ByteBuffer bb, BigInteger bigInteger, int length) throws IOException {
		// Get big-endian two's compliment representation of big integer
		byte[] bigInt = bigInteger.toByteArray();

		// Remove leading zero bytes
		int skipZeroPos = 0;

		for (int i = 0; i < bigInt.length; i++) {
			if (bigInt[i] != 0) {
				break;
			}
			skipZeroPos++;
		}

		byte[] tmp = new byte[bigInt.length - skipZeroPos];

		System.arraycopy(bigInt, skipZeroPos, tmp, 0, tmp.length);

		bigInt = tmp;

		// Convert to little-endian
		reverseBytes(bigInt);

		// Pad out byte array with zeros
		int padByteLength = length - bigInt.length;

		if (padByteLength > 0) {
			tmp = new byte[length];
			System.arraycopy(bigInt, 0, tmp, 0, bigInt.length);
			bigInt = tmp;
		}

		bb.put(bigInt);
	}

	private static void reverseBytes(byte[] bytes) {
		int halfWay = bytes.length / 2;
		for (int i = 0; i < halfWay; i++) {
			byte b = bytes[i];
			bytes[i] = bytes[bytes.length - 1 - i];
			bytes[bytes.length - 1 - i] = b;
		}
	}
}
