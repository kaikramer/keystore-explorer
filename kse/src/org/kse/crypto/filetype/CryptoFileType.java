/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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

import java.util.ResourceBundle;

/**
 * Enumeration of Crypto File Types recognised by the CryptoFileUtil class.
 *
 */
public enum CryptoFileType {
	/** JKS KeyStore */
	JKS_KS("CryptoFileType.JksKs"),

	/** JCEKS KeyStore */
	JCEKS_KS("CryptoFileType.JceksKs"),

	/** PKCS #12 KeyStore */
	PKCS12_KS("CryptoFileType.Pkcs12Ks"),

	/** BKS-V1 KeyStore */
	BKS_V1_KS("CryptoFileType.BksV1Ks"),

	/** BKS KeyStore */
	BKS_KS("CryptoFileType.BksKs"),

	/** BCFKS FIPS KeyStore */
	BCFKS_KS("CryptoFileType.BcfKs"),

	/** UBER KeyStore */
	UBER_KS("CryptoFileType.UberKs"),

	/** Certificate */
	CERT("CryptoFileType.Certificate"),

	/** PKCS #10 Certificate Signing Request */
	PKCS10_CSR("CryptoFileType.Pkcs10Csr"),

	/** SPKAC Certificate Signing Request */
	SPKAC_CSR("CryptoFileType.SpkacCsr"),

	/** CRL */
	CRL("CryptoFileType.Crl"),

	/** Encrypted PKCS #8 Private Key */
	ENC_PKCS8_PVK("CryptoFileType.EncPkcs8Pvk"),

	/** Unencrypted PKCS #8 Private Key */
	UNENC_PKCS8_PVK("CryptoFileType.UnencPkcs8Pvk"),

	/** Encrypted PVK Microsoft Private Key */
	ENC_MS_PVK("CryptoFileType.EncMsPvk"),

	/** Unencrypted Microsoft PVK Private Key */
	UNENC_MS_PVK("CryptoFileType.UnencMsPvk"),

	/** Encrypted OpenSSL Private Key */
	ENC_OPENSSL_PVK("CryptoFileType.EncOpenSslPvk"),

	/** Unencrypted OpenSSL Private Key */
	UNENC_OPENSSL_PVK("CryptoFileType.UnencOpenSslPvk"),

	/** OpenSSL Public Key */
	OPENSSL_PUB("CryptoFileType.OpenSslPub"),

	/** JAR file (possibly signed and containing certificates) */
	JAR("CryptoFileType.Jar"),

	/** Unknown file type */
	UNKNOWN("CryptoFileType.Unknown");

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/filetype/resources");
	private String friendlyKey;

	CryptoFileType(String friendlyKey) {
		this.friendlyKey = friendlyKey;
	}

	/**
	 * Get type's friendly name.
	 *
	 * @return Friendly name
	 */
	public String friendly() {
		return res.getString(friendlyKey);
	}
}
