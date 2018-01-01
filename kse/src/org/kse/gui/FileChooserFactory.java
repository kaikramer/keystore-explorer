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
package org.kse.gui;

import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JFileChooser;

import org.kse.utilities.os.OperatingSystem;

/**
 * Simple factory that returns JFileChooser objects for the requested security
 * file types. Basically just supplies a JFileChooser object with the file
 * filter box completed appropriately.
 *
 */
public class FileChooserFactory {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

	public static final String KEYSTORE_EXT_1 = "ks";
	public static final String KEYSTORE_EXT_2 = "keystore";
	public static final String JKS_EXT = "jks";
	public static final String JCEKS_EXT = "jceks";
	public static final String BKS_EXT = "bks";
	public static final String UBER_EXT = "uber";
	public static final String PKCS12_KEYSTORE_EXT_1 = "pfx";
	public static final String PKCS12_KEYSTORE_EXT_2 = "p12";
	public static final String X509_EXT_1 = "cer";
	public static final String X509_EXT_2 = "crt";
	public static final String PKCS7_EXT_1 = "p7b";
	public static final String PKCS7_EXT_2 = "p7c";
	public static final String PKI_PATH_EXT = "pkipath";
	public static final String SPC_EXT = "spc";
	public static final String CET_EXT = "cet";
	public static final String PKCS8_EXT = "pkcs8";
	public static final String PVK_EXT = "pvk";
	public static final String OPENSSL_PVK_EXT = "key";
	public static final String PUBLIC_KEY_EXT = "pub";
	public static final String PKCS10_CSR_EXT_1 = "p10";
	public static final String PKCS10_CSR_EXT_2 = "csr";
	public static final String SPKAC_CSR_EXT = "spkac";
	public static final String CA_REPLY_EXT = "p7r";
	public static final String CRL_EXT = "crl";
	public static final String JAR_EXT = "jar";
	public static final String ZIP_EXT = "zip";
	public static final String JAD_EXT = "jad";
	public static final String LIB_DLL_EXT = "dll";
	public static final String LIB_SO_EXT = "so";
	public static final String LIB_DYLIB_EXT = "dylib";

	private static final String KEYSTORE_FILE_DESC = MessageFormat.format(
			res.getString("FileChooserFactory.KeyStoreFiles"), KEYSTORE_EXT_1, KEYSTORE_EXT_2, JKS_EXT, JCEKS_EXT,
			BKS_EXT, UBER_EXT);

	private static final String X509_FILE_DESC = MessageFormat.format(
			res.getString("FileChooserFactory.CertificateFiles"), X509_EXT_1, X509_EXT_2);

	private static final String PKCS7_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.Pkcs7Files"),
			PKCS7_EXT_1, PKCS7_EXT_2);

	private static final String PKI_PATH_FILE_DESC = MessageFormat.format(
			res.getString("FileChooserFactory.PkiPathFiles"), PKI_PATH_EXT);

	private static final String SPC_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.SpcFiles"),
			SPC_EXT);

	private static final String CET_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.CetFiles"),
			CET_EXT);

	private static final String PKCS12_FILE_DESC = MessageFormat.format(
			res.getString("FileChooserFactory.Pkcs12Files"), PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2);

	private static final String PKCS8_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.Pkcs8Files"),
			PKCS8_EXT);

	private static final String PVK_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.PvkFiles"),
			PVK_EXT);

	private static final String OPENSSL_PVK_FILE_DESC = MessageFormat.format(
			res.getString("FileChooserFactory.OpenSslPvkFiles"), OPENSSL_PVK_EXT);

	private static final String PUBLIC_KEY_FILE_DESC = MessageFormat.format(
			res.getString("FileChooserFactory.OpenSslPvkFiles"), PUBLIC_KEY_EXT);

	private static final String PKCS10_CSR_FILE_DESC = MessageFormat.format(
			res.getString("FileChooserFactory.Pkcs10CsrFiles"), PKCS10_CSR_EXT_1, PKCS10_CSR_EXT_2);

	private static final String SPKAC_CSR_FILE_DESC = MessageFormat.format(
			res.getString("FileChooserFactory.SpkacCsrFiles"), SPKAC_CSR_EXT);

	private static final String CA_REPLY_FILE_DESC = MessageFormat.format(
			res.getString("FileChooserFactory.CaReplyFiles"), CA_REPLY_EXT);

	private static final String CRL_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.CrlFiles"),
			CRL_EXT);

	private static final String JAR_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.JarFiles"),
			JAR_EXT);

	private static final String ZIP_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.ZipFiles"),
			ZIP_EXT);

	private static final String JAD_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.JadFiles"),
			JAD_EXT);

	private static final String LIB_DLL_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.LibDllFiles"),
			LIB_DLL_EXT);

	private static final String LIB_SO_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.LibSoFiles"),
			LIB_SO_EXT);

	private static final String LIB_DYLIB_FILE_DESC = MessageFormat.format(res.getString("FileChooserFactory.LibDylibFiles"),
			LIB_DYLIB_EXT);

	private FileChooserFactory() {
	}

	/**
	 * Get a JFileChooser filtered for KeyStore files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getKeyStoreFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2 },
				PKCS12_FILE_DESC));
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { KEYSTORE_EXT_1, KEYSTORE_EXT_2, JKS_EXT,
				JCEKS_EXT, BKS_EXT, UBER_EXT }, KEYSTORE_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for X.509 Certificate files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getX509FileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { X509_EXT_1, X509_EXT_2 }, X509_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PKCS #7 Certificate files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getPkcs7FileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PKCS7_EXT_1, PKCS7_EXT_2 }, PKCS7_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PKI Path Certificate files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getPkiPathFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PKI_PATH_EXT }, PKI_PATH_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for SPC Certificate files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getSpcFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { SPC_EXT }, SPC_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for CET files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getCetFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { CET_EXT }, CET_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for Certificate and PKCS #7 Certificate
	 * files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getCertFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { SPC_EXT }, SPC_FILE_DESC));
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PKI_PATH_EXT }, PKI_PATH_FILE_DESC));
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PKCS7_EXT_1, PKCS7_EXT_2 }, PKCS7_FILE_DESC));
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { X509_EXT_1, X509_EXT_2 }, X509_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PKCS #12 files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getPkcs12FileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2 },
				PKCS12_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PKCS #8 files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getPkcs8FileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PKCS8_EXT }, PKCS8_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PVK files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getPvkFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PVK_EXT }, PVK_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for OpenSSL private key files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getOpenSslPvkFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { OPENSSL_PVK_EXT }, OPENSSL_PVK_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for public key files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getPublicKeyFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PUBLIC_KEY_EXT }, PUBLIC_KEY_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for CSR files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getCsrFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(SPKAC_CSR_EXT, SPKAC_CSR_FILE_DESC));
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PKCS10_CSR_EXT_1, PKCS10_CSR_EXT_2 },
				PKCS10_CSR_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PKCS #10 CSR files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getPkcs10FileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { PKCS10_CSR_EXT_1, PKCS10_CSR_EXT_2 },
				PKCS10_CSR_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for SPKAC CSR files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getSpkacFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(SPKAC_CSR_EXT, SPKAC_CSR_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for CA reply files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getCaReplyFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(CA_REPLY_EXT, CA_REPLY_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for CRL files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getCrlFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(CRL_EXT, CRL_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for JAR and ZIP files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getArchiveFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { ZIP_EXT }, ZIP_FILE_DESC));
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { JAR_EXT }, JAR_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for ZIP files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getZipFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { ZIP_EXT }, ZIP_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for JAD files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getJadFileChooser() {
		JFileChooser chooser = getFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { JAD_EXT }, JAD_FILE_DESC));
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for library files.
	 *
	 * @return JFileChooser object
	 */
	public static JFileChooser getLibFileChooser() {
		JFileChooser chooser = getFileChooser();

		if (OperatingSystem.isWindows()) {
			chooser.addChoosableFileFilter(new FileExtFilter(new String[] { LIB_DLL_EXT }, LIB_DLL_FILE_DESC));
		} else if (OperatingSystem.isMacOs()) {
			chooser.addChoosableFileFilter(new FileExtFilter(new String[] { LIB_DYLIB_EXT }, LIB_DYLIB_FILE_DESC));
		} else if (OperatingSystem.isLinux() || OperatingSystem.isUnix()) {
			chooser.addChoosableFileFilter(new FileExtFilter(new String[] { LIB_SO_EXT }, LIB_SO_FILE_DESC));
		}

		return chooser;
	}

	private static JFileChooser getFileChooser() {
		return JavaFXFileChooser.isFxAvailable() ? new JavaFXFileChooser() : new JFileChooser();
	}

}
