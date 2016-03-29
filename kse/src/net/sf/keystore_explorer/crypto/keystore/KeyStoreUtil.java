/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2016 Kai Kramer
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
package net.sf.keystore_explorer.crypto.keystore;

import static net.sf.keystore_explorer.crypto.SecurityProvider.APPLE;
import static net.sf.keystore_explorer.crypto.SecurityProvider.BOUNCY_CASTLE;
import static net.sf.keystore_explorer.crypto.SecurityProvider.MS_CAPI;
import static net.sf.keystore_explorer.crypto.keypair.KeyPairType.EC;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

import org.apache.commons.io.IOUtils;

import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.BKS;
import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.BKS_V1;
import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.KEYCHAIN;
import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.UBER;

import net.sf.keystore_explorer.ApplicationSettings;
import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.Password;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileUtil;

/**
 * Provides utility methods for loading/saving KeyStores. The BouncyCastle
 * provider must be added before using this class to create or load a PKCS12,
 * BKS or UBER type KeyStores.
 *
 */
public final class KeyStoreUtil {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/crypto/keystore/resources");

	private KeyStoreUtil() {
	}

	/**
	 * Create a new, empty KeyStore.
	 *
	 * @param keyStoreType
	 *            The KeyStore type to create
	 * @return The KeyStore
	 * @throws CryptoException
	 *             Problem encountered creating the KeyStore
	 * @throws IOException
	 *             An I/O error occurred
	 */
	public static KeyStore create(KeyStoreType keyStoreType) throws CryptoException, IOException {
		if (!keyStoreType.isFileBased()) {
			throw new CryptoException(MessageFormat.format(res.getString("NoCreateKeyStoreNotFile.exception.message"),
					keyStoreType.jce()));
		}

		KeyStore keyStore = getKeyStoreInstance(keyStoreType);

		try {
			keyStore.load(null, null);
		} catch (CertificateException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					keyStoreType), ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					keyStoreType), ex);
		}

		return keyStore;
	}

	/**
	 * Load a KeyStore, auto-detecting the type, from a file accessed by a
	 * password.
	 *
	 * @param keyStoreFile
	 *            File to load KeyStore from
	 * @param password
	 *            Password of the KeyStore
	 * @return The KeyStore or null if file did not contain a KeyStore of a
	 *         recognised type
	 * @throws KeyStoreLoadException
	 *             Problem encountered loading the KeyStore as the auto-detected
	 *             type
	 * @throws CryptoException
	 *             Problem encountered loading the KeyStore
	 * @throws FileNotFoundException
	 *             If the KeyStore file does not exist, is a directory rather
	 *             than a regular file, or for some other reason cannot be
	 *             opened for reading
	 */
	public static KeyStore load(File keyStoreFile, Password password) throws CryptoException,
	FileNotFoundException {
		KeyStoreType keyStoreType = null;

		try {
			keyStoreType = CryptoFileUtil.detectKeyStoreType(new FileInputStream(keyStoreFile));
		} catch (FileNotFoundException ex) {
			throw ex;
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoLoadKeyStore.exception.message"), ex);
		}

		if (keyStoreType == null) {
			return null;
		}

		return load(keyStoreFile, password, keyStoreType);
	}

	/**
	 * Load a KeyStore from a file accessed by a password.
	 *
	 * @param keyStoreFile
	 *            File to load KeyStore from
	 * @param password
	 *            Password of the KeyStore
	 * @param keyStoreType
	 *            The type of the KeyStore to open
	 * @return The KeyStore
	 * @throws KeyStoreLoadException
	 *             Problem encountered loading the KeyStore as the specified
	 *             type
	 * @throws CryptoException
	 *             Problem encountered loading the KeyStore
	 * @throws FileNotFoundException
	 *             If the KeyStore file does not exist, is a directory rather
	 *             than a regular file, or for some other reason cannot be
	 *             opened for reading
	 */
	public static KeyStore load(File keyStoreFile, Password password, KeyStoreType keyStoreType)
			throws CryptoException, FileNotFoundException {
		if (!keyStoreType.isFileBased()) {
			throw new CryptoException(MessageFormat.format(res.getString("NoLoadKeyStoreNotFile.exception.message"),
					keyStoreType.jce()));
		}

		FileInputStream fis = new FileInputStream(keyStoreFile);

		KeyStore keyStore = getKeyStoreInstance(keyStoreType);

		try {
			keyStore.load(fis, password.toCharArray());
		} catch (CertificateException ex) {
			throw new KeyStoreLoadException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					keyStoreType), ex, keyStoreType);
		} catch (NoSuchAlgorithmException ex) {
			throw new KeyStoreLoadException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					keyStoreType), ex, keyStoreType);
		} catch (FileNotFoundException ex) {
			throw ex;
		} catch (IOException ex) {
			throw new KeyStoreLoadException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					keyStoreType), ex, keyStoreType);
		} finally {
			IOUtils.closeQuietly(fis);
		}

		return keyStore;
	}

	/**
	 * Is Apple Keychain supported?
	 *
	 * @return True if it is, false otherwise
	 */
	public static boolean isAppleKeychainSupported() {
		return Security.getProvider(APPLE.jce()) != null;
	}

	/**
	 * Load the Apple Keychain as a KeyStore. The KeyStore is not file based and
	 * therefore does not need to be saved.
	 *
	 * @return The Keychain as a KeyStore
	 * @throws CryptoException
	 *             Problem encountered loading the KeyStore
	 */
	public static KeyStore loadAppleKeychain() throws CryptoException {
		if (!isAppleKeychainSupported()) {
			throw new CryptoException(res.getString("AppleKeychainNotSupported.exception.message"));
		}

		KeyStore keyStore = null;

		try {
			keyStore = KeyStore.getInstance(KEYCHAIN.jce(), APPLE.jce());
		} catch (KeyStoreException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoCreateKeyStore.exception.message"),
					KEYCHAIN.jce()), ex);
		} catch (NoSuchProviderException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoCreateKeyStore.exception.message"),
					KEYCHAIN.jce()), ex);
		}

		try {
			keyStore.load(null, null);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					KEYCHAIN.jce()), ex);
		} catch (CertificateException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					KEYCHAIN.jce()), ex);
		} catch (IOException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					KEYCHAIN.jce()), ex);
		}

		return keyStore;
	}

	/**
	 * Are MSCAPI Stores supported?
	 *
	 * @return True if they are, false otherwise
	 */
	public static boolean areMsCapiStoresSupported() {
		return Security.getProvider(MS_CAPI.jce()) != null;
	}

	/**
	 * Load an MS CAPI Store as a KeyStore. The KeyStore is not file based and
	 * therefore does not need to be saved.
	 *
	 * @param msCapiStoreType
	 *            MS CAPI Store Type
	 * @return The MS CAPI Store as a KeyStore
	 * @throws CryptoException
	 *             Problem encountered loading the KeyStore
	 */
	public static KeyStore loadMsCapiStore(MsCapiStoreType msCapiStoreType) throws CryptoException {
		if (!areMsCapiStoresSupported()) {
			// May previously have been set on an MSCAPI supporting JRE
			ApplicationSettings.getInstance().setUseWindowsTrustedRootCertificates(false);
			throw new CryptoException(res.getString("MsCapiStoresNotSupported.exception.message"));
		}

		KeyStore keyStore = null;

		try {
			keyStore = KeyStore.getInstance(msCapiStoreType.jce(), MS_CAPI.jce());
		} catch (KeyStoreException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoCreateKeyStore.exception.message"),
					msCapiStoreType.jce()), ex);
		} catch (NoSuchProviderException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoCreateKeyStore.exception.message"),
					msCapiStoreType.jce()), ex);
		}

		try {
			keyStore.load(null, null);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					msCapiStoreType.jce()), ex);
		} catch (CertificateException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					msCapiStoreType.jce()), ex);
		} catch (IOException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoLoadKeyStoreType.exception.message"),
					msCapiStoreType.jce()), ex);
		}

		// apply workaround for duplicate aliases
		fixDuplicateMSCAPIAliases(keyStore);

		return keyStore;
	}

	/**
	 * Fix problem with duplicate key store aliases in MSCAPI store type by adding an unique postfix.
	 *
	 * NOTE: This code relies on non-public implementation details of sun.security.mscapi.KeyStore which might change in
	 * future Java releases!
	 *
	 * @param keyStore
	 */
	private static void fixDuplicateMSCAPIAliases(KeyStore keyStore) {
		try {
			Field keyStoreSpiField = keyStore.getClass().getDeclaredField("keyStoreSpi");
			keyStoreSpiField.setAccessible(true);
			KeyStoreSpi keyStoreSpi = (KeyStoreSpi) keyStoreSpiField.get(keyStore);

			Field entriesField = keyStoreSpi.getClass().getEnclosingClass().getDeclaredField("entries");
			entriesField.setAccessible(true);
			Collection<?> entries = (Collection<?>) entriesField.get(keyStoreSpi);
			Map<String, Object> aliases = new HashMap<String, Object>();

			for (Object entry : entries) {

				Field aliasField = entry.getClass().getDeclaredField("alias");
				aliasField.setAccessible(true);
				String alias = (String) aliasField.get(entry);

				// if duplicate was found, add postfix to both entries
				if (aliases.containsKey(alias.toLowerCase())) {
					addCertHashPostfix(aliases.get(alias.toLowerCase()));
					addCertHashPostfix(entry);
				} else {
					// add first occurence of every alias to map
					aliases.put(alias.toLowerCase(), entry);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void addCertHashPostfix(Object entry)
			throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {

		Field certChainField = entry.getClass().getDeclaredField("certChain");
		certChainField.setAccessible(true);
		X509Certificate[] certificates = (X509Certificate[]) certChainField.get(entry);

		String hashCode = Integer.toString(Math.abs(certificates[0].hashCode()), 16);

		Field aliasField = entry.getClass().getDeclaredField("alias");
		aliasField.setAccessible(true);
		String alias = (String) aliasField.get(entry);

		String postfix = " [" + hashCode.substring(0, 4) + "]";

		if (!alias.endsWith(postfix)) {
			aliasField.set(entry, alias + postfix);
		}
	}


	/**
	 * Save a KeyStore to a file protected by a password.
	 *
	 * @param keyStore
	 *            The KeyStore
	 * @param keyStoreFile
	 *            The file to save the KeyStore to
	 * @param password
	 *            The password to protect the KeyStore with
	 * @throws CryptoException
	 *             Problem encountered saving the KeyStore
	 * @throws FileNotFoundException
	 *             If the KeyStore file exists but is a directory rather than a
	 *             regular file, does not exist but cannot be created, or cannot
	 *             be opened for any other reason
	 * @throws IOException
	 *             An I/O error occurred
	 */
	public static void save(KeyStore keyStore, File keyStoreFile, Password password) throws CryptoException,
	IOException {
		KeyStoreType keyStoreType = KeyStoreType.resolveJce(keyStore.getType());

		if (!keyStoreType.isFileBased()) {
			throw new CryptoException(MessageFormat.format(res.getString("NoSaveKeyStoreNotFile.exception.message"),
					keyStoreType.jce()));
		}

		FileOutputStream fos = null;

		fos = new FileOutputStream(keyStoreFile);

		try {
			keyStore.store(fos, password.toCharArray());
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoSaveKeyStore.exception.message"), ex);
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("NoSaveKeyStore.exception.message"), ex);
		} catch (CertificateException ex) {
			throw new CryptoException(res.getString("NoSaveKeyStore.exception.message"), ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(res.getString("NoSaveKeyStore.exception.message"), ex);
		} finally {
			IOUtils.closeQuietly(fos);
		}
	}

	/**
	 * Does the supplied KeyStore contain any key entries? ie any entries that
	 * contain a key with no certificate chain.
	 *
	 * @param keyStore
	 *            KeyStore
	 * @return True if it does
	 * @throws CryptoException
	 *             Problem occurred checking the KeyStore
	 */
	public static boolean containsKey(KeyStore keyStore) throws CryptoException {
		try {
			Enumeration<String> aliases = keyStore.aliases();

			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();

				if (isKeyEntry(alias, keyStore)) {
					return true;
				}
			}

			return false;
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("NoCheckKeyStoreKeys.exception.message"), ex);
		}
	}

	/**
	 * Is the named entry in the KeyStore a key pair entry?
	 *
	 * @param alias
	 *            Alias
	 * @param keyStore
	 *            KeyStore
	 * @return True if it is, false otherwise
	 * @throws KeyStoreException
	 *             If there was a problem accessing the KeyStore.
	 */
	public static boolean isKeyPairEntry(String alias, KeyStore keyStore) throws KeyStoreException {
		return keyStore.isKeyEntry(alias)
				&& keyStore.getCertificateChain(alias) != null && keyStore.getCertificateChain(alias).length != 0;
	}

	/**
	 * Is the named entry in the KeyStore a key entry?
	 *
	 * @param alias
	 *            Alias
	 * @param keyStore
	 *            KeyStore
	 * @return True if it is, false otherwise
	 * @throws KeyStoreException
	 *             If there was a problem accessing the KeyStore.
	 */
	public static boolean isKeyEntry(String alias, KeyStore keyStore) throws KeyStoreException {
		return keyStore.isKeyEntry(alias)
				&& (keyStore.getCertificateChain(alias) == null || keyStore.getCertificateChain(alias).length == 0);
	}

	/**
	 * Is the named entry in the KeyStore a trusted certificate entry?
	 *
	 * @param alias
	 *            Alias
	 * @param keyStore
	 *            KeyStore
	 * @return True if it is, false otherwise
	 * @throws KeyStoreException
	 *             If there was a problem accessing the KeyStore.
	 */
	public static boolean isTrustedCertificateEntry(String alias, KeyStore keyStore) throws KeyStoreException {
		return keyStore.isCertificateEntry(alias);
	}

	/**
	 * Copy a KeyStore.
	 *
	 * @param keyStore
	 *            KeyStore to copy
	 * @return Copy
	 * @throws CryptoException
	 *             Problem encountered copying the KeyStore
	 */
	public static KeyStore copy(KeyStore keyStore) throws CryptoException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {
			char[] emptyPassword = {};

			keyStore.store(baos, emptyPassword);

			KeyStore theCopy = KeyStoreUtil.create(KeyStoreType.resolveJce(keyStore.getType()));
			theCopy.load(new ByteArrayInputStream(baos.toByteArray()), emptyPassword);

			return theCopy;
		} catch (CryptoException ex) {
			throw new CryptoException(res.getString("NoCopyKeyStore.exception.message"), ex);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoCopyKeyStore.exception.message"), ex);
		} catch (IllegalStateException ex) {
			throw new CryptoException(res.getString("NoCopyKeyStore.exception.message"), ex);
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoCopyKeyStore.exception.message"), ex);
		}
	}

	private static KeyStore getKeyStoreInstance(KeyStoreType keyStoreType) throws CryptoException {
		try {
			if (keyStoreType == BKS || keyStoreType == BKS_V1 || keyStoreType == UBER) {
				if (Security.getProvider(BOUNCY_CASTLE.jce()) == null) {
					throw new CryptoException(MessageFormat.format(res.getString("NoProvider.exception.message"),
							BOUNCY_CASTLE.jce()));
				}

				return KeyStore.getInstance(keyStoreType.jce(), BOUNCY_CASTLE.jce());
			} else {
				return KeyStore.getInstance(keyStoreType.jce());
			}
		} catch (KeyStoreException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoCreateKeyStore.exception.message"),
					keyStoreType), ex);
		} catch (NoSuchProviderException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoProvider.exception.message"),
					BOUNCY_CASTLE.jce()));
		}
	}

	/**
	 * Is the key pair entry identified by alias a EC key pair?
	 *
	 * @param alias
	 *            Alias of key pair entry
	 * @param keyStore
	 *            KeyStore that contains the key pair
	 * @return True, if alias is a EC key pair
	 * @throws KeyStoreException
	 *                If there was a problem accessing the KeyStore.
	 */
	public static boolean isECKeyPair(String alias, KeyStore keyStore) throws KeyStoreException {

		if (!isKeyPairEntry(alias, keyStore)) {
			return false;
		}

		Certificate certificate = keyStore.getCertificate(alias);
		String algorithm = certificate.getPublicKey().getAlgorithm();
		return algorithm.equals(EC.jce());
	}
}
