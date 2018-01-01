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
package org.kse.crypto.keystore;

import static org.kse.crypto.filetype.CryptoFileType.BKS_KS;
import static org.kse.crypto.filetype.CryptoFileType.BKS_V1_KS;
import static org.kse.crypto.filetype.CryptoFileType.JCEKS_KS;
import static org.kse.crypto.filetype.CryptoFileType.JKS_KS;
import static org.kse.crypto.filetype.CryptoFileType.PKCS12_KS;
import static org.kse.crypto.filetype.CryptoFileType.UBER_KS;

import java.util.ResourceBundle;

import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.filetype.CryptoFileType;

/**
 * Enumeration of KeyStore Types supported by the KeyStoreUtil class.
 *
 */
public enum KeyStoreType {

	JKS("JKS", "KeyStoreType.Jks", true, JKS_KS),
	JCEKS("JCEKS", "KeyStoreType.Jceks", true, JCEKS_KS),
	PKCS12("PKCS12", "KeyStoreType.Pkcs12", true, PKCS12_KS),
	BKS_V1("BKS-V1", "KeyStoreType.BksV1", true, BKS_V1_KS),
	BKS("BKS", "KeyStoreType.Bks", true, BKS_KS),
	UBER("UBER", "KeyStoreType.Uber", true, UBER_KS),
	KEYCHAIN("KeychainStore", "KeyStoreType.AppleKeyChain", false, null),
	MS_CAPI_PERSONAL("Windows-MY", "KeyStoreType.MscapiPersonalCerts", false, null),
	MS_CAPI_ROOT("Windows-ROOT", "Windows Root Certificates", false, null),
	PKCS11("PKCS11", "KeyStoreType.Pkcs11", false, null);

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/keystore/resources");
	private String jce;
	private String friendlyKey;
	private boolean fileBased;
	private CryptoFileType cryptoFileType;

	KeyStoreType(String jce, String friendlyKey, boolean fileBased, CryptoFileType cryptoFileType) {
		this.jce = jce;
		this.friendlyKey = friendlyKey;
		this.fileBased = fileBased;
		this.cryptoFileType = cryptoFileType;
	}

	/**
	 * Get KeyStore type JCE name.
	 *
	 * @return JCE name
	 */
	public String jce() {
		return jce;
	}

	/**
	 * KeyStore type friendly name.
	 *
	 * @return Friendly name
	 */
	public String friendly() {
		return res.getString(friendlyKey);
	}

	/**
	 * Is KeyStore type file based?
	 *
	 * @return True if it is, false otherwise
	 */
	public boolean isFileBased() {
		return fileBased;
	}

	/**
	 * Are key store entries password protected?
	 *
	 * @return True if it has, false otherwise
	 */
	public boolean hasEntryPasswords() {
		return this != PKCS11 && this != MS_CAPI_PERSONAL;
	}

	/*
	 * Are private keys exportable for this keystore type?
	 *
	 * @return True if private keys are exportable, false otherwise
	 */
	public boolean hasExportablePrivateKeys() {
		return this != PKCS11 && this != MS_CAPI_PERSONAL;
	}

	/**
	 * Does this KeyStore type support secret key entries?
	 *
	 * @return True, if secret key entries are supported by this KeyStore type
	 */
	public boolean supportsKeyEntries() {
		return this == JCEKS || this == BKS || this == BKS_V1 || this == UBER;
	}

	/**
	 * Does this KeyStore type support ECC key pair entries?
	 *
	 * @return True, if ECC supported
	 */
	public boolean supportsECC() {
		return EccUtil.isECAvailable(this);
	}

	/**
	 * Does this KeyStore type support a certain named curve?
	 *
	 * @return True, if curve is supported
	 */
	public boolean supportsNamedCurve(String curveName) {
		return EccUtil.isCurveAvailable(curveName, this);
	}

	/**
	 * Resolve the supplied JCE name to a matching KeyStore type.
	 *
	 * @param jce
	 *            JCE name
	 * @return KeyStore type or null if none
	 */
	public static KeyStoreType resolveJce(String jce) {
		for (KeyStoreType keyStoreType : values()) {
			if (jce.equals(keyStoreType.jce())) {
				return keyStoreType;
			}
		}

		return null;
	}

	/**
	 * Get crypto file type.
	 *
	 * @return Crypto file type or null if KeyStore type is not file based
	 */
	public CryptoFileType getCryptoFileType() {
		return cryptoFileType;
	}

	/**
	 * Returns JCE name.
	 *
	 * @return JCE name
	 */
	@Override
	public String toString() {
		return jce();
	}
}
