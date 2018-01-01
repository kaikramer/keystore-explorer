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
package org.kse.crypto.filetype;

import static org.kse.crypto.csr.CsrType.PKCS10;
import static org.kse.crypto.filetype.CryptoFileType.CERT;
import static org.kse.crypto.filetype.CryptoFileType.CRL;
import static org.kse.crypto.filetype.CryptoFileType.ENC_MS_PVK;
import static org.kse.crypto.filetype.CryptoFileType.ENC_OPENSSL_PVK;
import static org.kse.crypto.filetype.CryptoFileType.ENC_PKCS8_PVK;
import static org.kse.crypto.filetype.CryptoFileType.OPENSSL_PUB;
import static org.kse.crypto.filetype.CryptoFileType.UNENC_MS_PVK;
import static org.kse.crypto.filetype.CryptoFileType.UNENC_OPENSSL_PVK;
import static org.kse.crypto.filetype.CryptoFileType.UNENC_PKCS8_PVK;
import static org.kse.crypto.filetype.CryptoFileType.UNKNOWN;
import static org.kse.crypto.keystore.KeyStoreType.BKS;
import static org.kse.crypto.keystore.KeyStoreType.BKS_V1;
import static org.kse.crypto.keystore.KeyStoreType.JCEKS;
import static org.kse.crypto.keystore.KeyStoreType.JKS;
import static org.kse.crypto.keystore.KeyStoreType.PKCS12;
import static org.kse.crypto.keystore.KeyStoreType.UBER;
import static org.kse.crypto.privatekey.EncryptionType.ENCRYPTED;
import static org.kse.crypto.privatekey.EncryptionType.UNENCRYPTED;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.kse.crypto.csr.CsrType;
import org.kse.crypto.csr.pkcs10.Pkcs10Util;
import org.kse.crypto.csr.spkac.Spkac;
import org.kse.crypto.csr.spkac.SpkacException;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.privatekey.EncryptionType;
import org.kse.crypto.privatekey.MsPvkUtil;
import org.kse.crypto.privatekey.OpenSslPvkUtil;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.crypto.publickey.OpenSslPubUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.utilities.io.ReadUtil;

/**
 * Provides utility methods for the detection of cryptographic file types.
 *
 */
public class CryptoFileUtil {
	private static final int JKS_MAGIC_NUMBER = 0xFEEDFEED;
	private static final int JCEKS_MAGIC_NUMBER = 0xCECECECE;

	/**
	 * Detect the cryptographic file type of the supplied input stream.
	 *
	 * @param is
	 *            Input stream to detect type for
	 * @return Type or null if file not of a recognised type
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public static CryptoFileType detectFileType(InputStream is) throws IOException {
		byte[] contents = ReadUtil.readFully(is);

		EncryptionType pkcs8EncType = Pkcs8Util.getEncryptionType(new ByteArrayInputStream(contents));

		if (pkcs8EncType != null) {
			if (pkcs8EncType == ENCRYPTED) {
				return ENC_PKCS8_PVK;
			} else if (pkcs8EncType == UNENCRYPTED) {
				return UNENC_PKCS8_PVK;
			}
		}

		EncryptionType msPvkEncType = MsPvkUtil.getEncryptionType(new ByteArrayInputStream(contents));

		if (msPvkEncType != null) {
			if (msPvkEncType == ENCRYPTED) {
				return ENC_MS_PVK;
			} else if (msPvkEncType == UNENCRYPTED) {
				return UNENC_MS_PVK;
			}
		}

		EncryptionType openSslPvkEncType = OpenSslPvkUtil.getEncryptionType(new ByteArrayInputStream(contents));

		if (openSslPvkEncType != null) {
			if (openSslPvkEncType == ENCRYPTED) {
				return ENC_OPENSSL_PVK;
			} else if (openSslPvkEncType == UNENCRYPTED) {
				return UNENC_OPENSSL_PVK;
			}
		}

		try {
			OpenSslPubUtil.load(new ByteArrayInputStream(contents));
			return OPENSSL_PUB;
		} catch (Exception ex) {
			// Ignore - not an OpenSSL public key file
		} catch (OutOfMemoryError ex) {
			// Ignore - not an OpenSSL public key file, some files cause the
			// heap space to fill up with the load call
		}

		try {
			if (X509CertUtil.loadCertificates(new ByteArrayInputStream(contents)).length > 0) {
				return CERT;
			}
		} catch (Exception ex) {
			// Ignore - not a certificate file
		}

		try {
			X509CertUtil.loadCRL(new ByteArrayInputStream(contents));
			return CRL;
		} catch (Exception ex) {
			// Ignore - not a CRL file
		}

		CsrType csrType = detectCsrType(contents);

		if (csrType != null) {
			return csrType.getCryptoFileType();
		}

		KeyStoreType keyStoreType = detectKeyStoreType(new ByteArrayInputStream(contents));

		if (keyStoreType != null) {
			return keyStoreType.getCryptoFileType();
		}

		// Not a recognised type
		return UNKNOWN;
	}

	private static CsrType detectCsrType(byte[] contents) throws IOException {
		try {
			Pkcs10Util.loadCsr(new ByteArrayInputStream(contents));
			return PKCS10;
		} catch (FileNotFoundException ex) {
			throw ex;
		} catch (Exception ex) {
			// Ignore - not a PKCS #10 file
		} catch (OutOfMemoryError ex) {
			// Ignore - not a PKCS #10 file, some files cause the heap space to
			// fill up with the load call
		}

		try {
			new Spkac(new ByteArrayInputStream(contents));
			return CsrType.SPKAC;
		} catch (SpkacException ex) {
			// Ignore - not an SPKAC file
		}

		// Not a recognised type
		return null;
	}

	/**
	 * Detect the KeyStore type contained in the supplied file.
	 *
	 * @param is
	 *            Input stream to detect type for
	 * @return KeyStore type or null if none matched
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public static KeyStoreType detectKeyStoreType(InputStream is) throws IOException {
		byte[] contents = ReadUtil.readFully(is);

		try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(contents))) {

			// If less than 4 bytes are available it isn't a KeyStore
			if (dis.available() < 4) {
				return null;
			}

			// Read first integer (4 bytes)
			int i1 = dis.readInt();

			// Test for JKS - starts with appropriate magic number
			if (i1 == JKS_MAGIC_NUMBER) {
				return JKS;
			}

			// Test for JCEKS - starts with appropriate magic number
			if (i1 == JCEKS_MAGIC_NUMBER) {
				return JCEKS;
			}

			// Test for BKS and UBER

			// Both start with a version number of 0, 1 or 2
			if ((i1 == 0) || (i1 == 1) || (i1 == 2)) {
				/*
				 * For BKS and UBER the last 20 bytes of the file are the SHA-1
				 * Hash while the byte before that is a ASN1Null (0) indicating
				 * the end of the store. UBER, however, encrypts the store
				 * content making it highly unlikely that the ASN1Null end byte
				 * will be preserved. Therefore if the 21st byte from the end of
				 * the file is a ASN1Null then the KeyStore is BKS
				 */

				if (contents.length < 26) {
					// Insufficient bytes to be BKS or UBER
					return null;
				}

				// Skip to 21st from last byte (file length minus 21 and the 4 bytes already read)
				dis.skip(contents.length - 25);

				// Read what may be the null byte
				if (dis.readByte() == 0) {
					// Found null byte - BKS/BKS-V1
					if (i1 == 1) {
						return BKS_V1;
					} else {
						return BKS;
					}
				} else {
					// No null byte - UBER
					return UBER;
				}
			}
		}

		// @formatter:off
		/*
		 * Test for PKCS #12. ASN.1 should look like this:
		 *
		 * PFX ::= ASN1Sequence { version ASN1Integer {v3(3)}(v3,...), authSafe
		 * ContentInfo, macData MacData OPTIONAL
		 */
		// @formatter:on

		ASN1Primitive pfx = null;
		try {
			pfx = ASN1Primitive.fromByteArray(contents);
		} catch (IOException e) {
			// if it cannot be parsed as ASN1, it is certainly not a pfx key store
			return null;
		}

		// Is a sequence...
		if ((pfx != null) && (pfx instanceof ASN1Sequence)) {
			// Has two or three components...
			ASN1Sequence sequence = (ASN1Sequence) pfx;

			if ((sequence.size() == 2) || (sequence.size() == 3)) {
				// ...the first of which is a version of 3
				ASN1Encodable firstComponent = sequence.getObjectAt(0);

				if (firstComponent instanceof ASN1Integer) {
					ASN1Integer version = (ASN1Integer) firstComponent;

					if (version.getValue().intValue() == 3) {
						return PKCS12;
					}
				}
			}
		}

		// KeyStore type not recognised
		return null;
	}
}
