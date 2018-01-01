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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.TreeMap;

import org.bouncycastle.util.encoders.Base64;
import org.kse.crypto.CryptoException;
import org.kse.utilities.io.CopyUtil;

/**
 * Class provides functionality to sign MIDlets.
 *
 */
public class MidletSigner {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/signing/resources");

	private static final String CRLF = "\r\n";

	// Message format template for JAD file attributes
	private static final String JAD_ATTR_TEMPLATE = "{0}: {1}";

	// MIDlet Certificate JAD attribute
	private static final String MIDLET_CERTIFICATE_ATTR = "MIDlet-Certificate-{0}-{1}";

	// MIDlet Certificate JAD attribute minus certificate chain number
	private static final String SUB_MIDLET_CERTIFICATE_ATTR = "MIDlet-Certificate-{0}-";

	// MIDlet JAR Manifest attribute
	private static final String MIDLET_JAR_RSA_SHA1_ATTR = "MIDlet-Jar-RSA-SHA1";

	private MidletSigner() {
	}

	/**
	 * Sign a MIDlet overwriting the supplied JAD file.
	 *
	 * @param jadFile
	 *            JAD file
	 * @param jarFile
	 *            JAR file
	 * @param privateKey
	 *            Private RSA key to sign with
	 * @param certificateChain
	 *            Certificate chain for private key
	 * @param certificateNumber
	 *            Certificate number
	 * @throws IOException
	 *             If an I/O problem occurs while signing the MIDlet
	 * @throws CryptoException
	 *             If a crypto problem occurs while signing the MIDlet
	 */
	public static void sign(File jadFile, File jarFile, RSAPrivateKey privateKey, X509Certificate[] certificateChain,
			int certificateNumber) throws IOException, CryptoException {
		File tmpFile = File.createTempFile("kse", "tmp");
		tmpFile.deleteOnExit();

		sign(jadFile, tmpFile, jarFile, privateKey, certificateChain, certificateNumber);

		CopyUtil.copyClose(new FileInputStream(tmpFile), new FileOutputStream(jadFile));

		tmpFile.delete();
	}

	/**
	 * Sign a JAD file outputting the modified JAD to a different file.
	 *
	 * @param jadFile
	 *            JAD file
	 * @param outputJadFile
	 *            Output JAD file
	 * @param jarFile
	 *            JAR file
	 * @param privateKey
	 *            Private RSA key to sign with
	 * @param certificateChain
	 *            Certificate chain for private key
	 * @param certificateNumber
	 *            Certificate number
	 * @throws IOException
	 *             If an I/O problem occurs while signing the MIDlet
	 * @throws CryptoException
	 *             If a crypto problem occurs while signing the MIDlet
	 */
	public static void sign(File jadFile, File outputJadFile, File jarFile, RSAPrivateKey privateKey,
			X509Certificate[] certificateChain, int certificateNumber) throws IOException, CryptoException {
		Properties jadProperties = readJadFile(jadFile);

		Properties newJadProperties = new Properties();

		// Copy over existing attrs (excepting digest and any certificates at
		// provided number)
		for (Enumeration<?> enumPropNames = jadProperties.propertyNames(); enumPropNames.hasMoreElements();) {
			String propName = (String) enumPropNames.nextElement();

			// Ignore digest attr
			if (propName.equals(MIDLET_JAR_RSA_SHA1_ATTR)) {
				continue;
			}

			// Ignore certificates at provided number
			if (propName.startsWith(MessageFormat.format(SUB_MIDLET_CERTIFICATE_ATTR, certificateNumber))) {
				continue;
			}

			newJadProperties.put(propName, jadProperties.getProperty(propName));
		}

		// Get certificate attrs
		for (int i = 0; i < certificateChain.length; i++) {
			X509Certificate certificate = certificateChain[i];
			String base64Cert = null;
			try {
				base64Cert = new String(Base64.encode(certificate.getEncoded()));
			} catch (CertificateEncodingException ex) {
				throw new CryptoException(res.getString("Base64CertificateFailed.exception.message"), ex);
			}

			String midletCertificateAttr = MessageFormat.format(MIDLET_CERTIFICATE_ATTR, certificateNumber, (i + 1));
			newJadProperties.put(midletCertificateAttr, base64Cert);
		}

		// Get signed Base 64 SHA-1 digest of JAR file as attr
		byte[] signedJarDigest = signJarDigest(jarFile, privateKey);
		String base64SignedJarDigest = new String(Base64.encode(signedJarDigest));
		newJadProperties.put(MIDLET_JAR_RSA_SHA1_ATTR, base64SignedJarDigest);

		// Sort properties alphabetically
		TreeMap<String, String> sortedJadProperties = new TreeMap<String, String>();

		for (Enumeration<?> names = newJadProperties.propertyNames(); names.hasMoreElements();) {
			String name = (String) names.nextElement();
			String value = newJadProperties.getProperty(name);

			sortedJadProperties.put(name, value);
		}

		// Write out new JAD properties to JAD file
		try (FileWriter fw = new FileWriter(outputJadFile)) {
			for (Iterator<Entry<String, String>> itrSorted = sortedJadProperties.entrySet().iterator(); itrSorted.hasNext();) {
				Entry<String, String> property = itrSorted.next();

				fw.write(MessageFormat.format(JAD_ATTR_TEMPLATE, property.getKey(), property.getValue()));
				fw.write(CRLF);
			}
		}
	}

	private static byte[] signJarDigest(File jarFile, RSAPrivateKey privateKey) throws CryptoException {

		// Create a SHA-1 signature for the supplied JAR file
		try (FileInputStream fis = new FileInputStream(jarFile)) {
			Signature signature = Signature.getInstance(SignatureType.SHA1_RSA.jce());
			signature.initSign(privateKey);

			byte buffer[] = new byte[1024];
			int read = 0;

			while ((read = fis.read(buffer)) != -1) {
				signature.update(buffer, 0, read);
			}

			return signature.sign();
		} catch (IOException ex) {
			throw new CryptoException(res.getString("JarDigestSignatureFailed.exception.message"), ex);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("JarDigestSignatureFailed.exception.message"), ex);
		}
	}

	/**
	 * Read the attributes of the supplied JAD file as properties.
	 *
	 * @param jadFile
	 *            JAD file
	 * @return JAD file's attributes as properties
	 * @throws IOException
	 *             If an I/O problem occurred or supplied file is not a JAD file
	 */
	public static Properties readJadFile(File jadFile) throws IOException {

		try (FileInputStream fileInputStream = new FileInputStream(jadFile);
				InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
				LineNumberReader lnr = new LineNumberReader(inputStreamReader)) {

			Properties jadProperties = new Properties();

			String line = null;
			while ((line = lnr.readLine()) != null) {
				int index = line.indexOf(": ");

				if (index == -1) {
					throw new IOException(res.getString("NoReadJadCorrupt.exception.message"));
				}

				String name = line.substring(0, index);
				String value = line.substring(index + 2);
				jadProperties.setProperty(name, value);
			}

			return jadProperties;
		}
	}
}
