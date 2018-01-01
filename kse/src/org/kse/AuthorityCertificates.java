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
package org.kse;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;

import org.kse.crypto.CryptoException;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.MsCapiStoreType;

/**
 * Singleton that maintains authority certificates KeyStores.
 *
 */
public class AuthorityCertificates {

	public static final String CACERTS_DEFAULT_PWD = "changeit";

	private static AuthorityCertificates authorityCertificates;
	private KeyStore caCertificates;
	private KeyStore windowsTrustedRootCertificates;

	private AuthorityCertificates() {
	}

	/**
	 * Get singleton instance of authority certificates.
	 *
	 * @return Authority certificates
	 */
	public static synchronized AuthorityCertificates getInstance() {
		if (authorityCertificates == null) {
			authorityCertificates = new AuthorityCertificates();
		}

		return authorityCertificates;
	}

	/**
	 * Get CA Certificates KeyStore. If not set this is not loaded. Instead load
	 * seperately and set it for future reference.
	 *
	 * @return CA Certificates KeyStore
	 */
	public KeyStore getCaCertificates() {
		return caCertificates;
	}

	/**
	 * Set CA Certificates KeyStore.
	 *
	 * @param caCertificates
	 *            CA Certificates KeyStore
	 */
	public void setCaCertificates(KeyStore caCertificates) {
		this.caCertificates = caCertificates;
	}

	/**
	 * Get the default location for the CA Certificates KeyStore.
	 *
	 * @return CA Certificates KeyStore default location
	 */
	public static File getDefaultCaCertificatesLocation() {
		String javaInstallDir = System.getProperty("java.home");
		String fileSep = System.getProperty("file.separator");
		File cacertsFile = new File(javaInstallDir, "lib" + fileSep + "security" + fileSep + "cacerts");
		try {
			return cacertsFile.getCanonicalFile();
		} catch (IOException e) {
			return cacertsFile;
		}
	}

	/**
	 * Get Windows Trusted Root Certificates KeyStore. If not set this is
	 * loaded.
	 *
	 * @return Windows Trusted Root Certificates KeyStore
	 * @throws CryptoException
	 *             If a problem occurred getting the KeyStore
	 */
	public KeyStore getWindowsTrustedRootCertificates() throws CryptoException {
		if (windowsTrustedRootCertificates == null) {
			windowsTrustedRootCertificates = KeyStoreUtil.loadMsCapiStore(MsCapiStoreType.ROOT);
		}

		return windowsTrustedRootCertificates;
	}
}
