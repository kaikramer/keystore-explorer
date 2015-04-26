/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2015 Kai Kramer
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
package net.sf.keystore_explorer.crypto.signing;

import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA1_DSA;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.LineNumberReader;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.digest.DigestType;
import net.sf.keystore_explorer.crypto.digest.DigestUtil;
import net.sf.keystore_explorer.utilities.io.CopyUtil;
import net.sf.keystore_explorer.utilities.io.SafeCloseUtil;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

/**
 * Class provides functionality to sign JAR files.
 *
 */
public class JarSigner extends Object {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/crypto/signing/resources");

	private static final String CRLF = "\r\n";

	// Message format template for manifest and signature file attributes
	private static final String ATTR_TEMPLATE = "{0}: {1}";

	// Manifest Version attribute
	private static final String MANIFEST_VERSION_ATTR = "Manifest-Version";

	// Manifest Version
	private static final String MANIFEST_VERSION = "1.0";

	// Created By attribute
	private static final String CREATED_BY_ATTR = "Created-By";

	// Digest attribute
	private static final String DIGEST_ATTR = "{0}-Digest";

	// Name attribute
	private static final String NAME_ATTR = "Name";

	// Digest Manifest attribute
	private static final String DIGEST_MANIFEST_ATTR = "{0}-Digest-Manifest";

	// Digest Manifest Main Attributes attribute
	private static final String DIGEST_MANIFEST_MAIN_ATTRIBUTES_ATTR = "{0}-Digest-Manifest-Main-Attributes";

	// Signature Version attribute
	private static final String SIGNATURE_VERSION_ATTR = "Signature-Version";

	// Signature Version
	private static final String SIGNATURE_VERSION = "1.0";

	// Manifest location in JAR file
	private static final String MANIFEST_LOCATION = "META-INF/MANIFEST.MF";

	// DSA siganture block extension
	private static final String DSA_SIG_BLOCK_EXT = "DSA";

	// RSA siganture block extension
	private static final String RSA_SIG_BLOCK_EXT = "RSA";

	// Signature file extension
	private static final String SIGNATURE_EXT = "SF";

	// Meta inf file location
	private static final String METAINF_FILE_LOCATION = "META-INF/{0}.{1}";

	private JarSigner() {
	}

	/**
	 * Sign a JAR file overwriting it with the signed JAR.
	 *
	 * @param jsrFile
	 *            JAR file to sign
	 * @param privateKey
	 *            Private key to sign with
	 * @param certificateChain
	 *            Certificate chain for private key
	 * @param signatureType
	 *            Signature type
	 * @param signatureName
	 *            Signature name
	 * @param signer
	 *            Signer
	 * @param digestType
	 *            Digest type
	 * @throws IOException
	 *             If an I/O problem occurs while signing the JAR file
	 * @throws CryptoException
	 *             If a crypto problem occurs while signing the JAR file
	 */
	public static void sign(File jsrFile, PrivateKey privateKey, X509Certificate[] certificateChain,
			SignatureType signatureType, String signatureName, String signer, DigestType digestType,
			Provider provider) throws IOException, CryptoException {
		File tmpFile = File.createTempFile("kse", "tmp");
		tmpFile.deleteOnExit();

		sign(jsrFile, tmpFile, privateKey, certificateChain, signatureType, signatureName, signer, digestType, provider);

		CopyUtil.copyClose(new FileInputStream(tmpFile), new FileOutputStream(jsrFile));

		tmpFile.delete();
	}

	/**
	 * Sign a JAR file outputting the signed JAR to a different file.
	 *
	 * @param jarFile
	 *            JAR file to sign
	 * @param signedJarFile
	 *            Output file for signed JAR
	 * @param privateKey
	 *            Private key to sign with
	 * @param certificateChain
	 *            Certificate chain for private key
	 * @param signatureType
	 *            Signature type
	 * @param signatureName
	 *            Signature name
	 * @param signer
	 *            Signer
	 * @param digestType
	 *            Digest type
	 * @throws IOException
	 *             If an I/O problem occurs while signing the JAR file
	 * @throws CryptoException
	 *             If a crypto problem occurs while signing the JAR file
	 */
	public static void sign(File jarFile, File signedJarFile, PrivateKey privateKey,
			X509Certificate[] certificateChain, SignatureType signatureType, String signatureName, String signer,
			DigestType digestType, Provider provider) throws IOException, CryptoException {
		JarFile jar = null;
		JarOutputStream jos = null;

		try {
			// Replace illegal characters in signature name
			signatureName = convertSignatureName(signatureName);

			// Create Jar File accessor for JAR to be signed
			jar = new JarFile(jarFile);

			// Write manifest content to here
			StringBuffer sbManifest = new StringBuffer();

			// Write out main attributes to manifest
			String manifestMainAttrs = getManifestMainAttrs(jar, signer);
			sbManifest.append(manifestMainAttrs);

			// Write out all entries' attributes to manifest
			String entryManifestAttrs = getManifestEntriesAttrs(jar);

			if (entryManifestAttrs.length() > 0) {
				// Only output if there are any
				sbManifest.append(entryManifestAttrs);
				sbManifest.append(CRLF);
			}

			// Write signature file to here
			StringBuffer sbSf = new StringBuffer();

			// Write out digests to manifest and signature file

			// Sign each JAR entry...
			for (Enumeration jarEntries = jar.entries(); jarEntries.hasMoreElements();) {
				JarEntry jarEntry = (JarEntry) jarEntries.nextElement();

				if (!jarEntry.isDirectory()) // Ignore directories
				{
					if (!ignoreJarEntry(jarEntry)) // Ignore some entries
													// (existing signature
													// files)
					{
						// Get the digest of the entry as manifest attributes
						String manifestEntry = getDigestManifestAttrs(jar, jarEntry, digestType);

						// Add it to the manifest string buffer
						sbManifest.append(manifestEntry);

						// Get the digest of manifest entries created above
						byte[] mdSf = DigestUtil.getMessageDigest(manifestEntry.getBytes(), digestType);
						byte[] mdSf64 = Base64.encode(mdSf);
						String mdSf64Str = new String(mdSf64);

						// Write this digest as entries in signature file
						sbSf.append(createAttributeText(NAME_ATTR, jarEntry.getName()));
						sbSf.append(CRLF);
						sbSf.append(createAttributeText(MessageFormat.format(DIGEST_ATTR, digestType.jce()), mdSf64Str));
						sbSf.append(CRLF);
						sbSf.append(CRLF);
					}
				}
			}

			/*
			 * Manifest file complete - get base 64 encoded digest of its
			 * content for inclusion in signature file
			 */
			byte[] manifest = sbManifest.toString().getBytes();

			byte[] digestMf = DigestUtil.getMessageDigest(manifest, digestType);
			String digestMfStr = new String(Base64.encode(digestMf));

			/*
			 * Get base 64 encoded digest of manifest's main attributes for
			 * incusion in signature file
			 */
			byte[] mainfestMainAttrs = manifestMainAttrs.getBytes();

			byte[] digestMfMainAttrs = DigestUtil.getMessageDigest(mainfestMainAttrs, digestType);
			String digestMfMainAttrsStr = new String(Base64.encode(digestMfMainAttrs));

			// Write out Manifest Digest, Created By and Signature Version to
			// start of signature
			// file
			sbSf.insert(0, CRLF);
			sbSf.insert(0, CRLF);
			sbSf.insert(0,
					createAttributeText(MessageFormat.format(DIGEST_MANIFEST_ATTR, digestType.jce()), digestMfStr));
			sbSf.insert(0, CRLF);
			sbSf.insert(
					0,
					createAttributeText(MessageFormat.format(DIGEST_MANIFEST_MAIN_ATTRIBUTES_ATTR, digestType.jce()),
							digestMfMainAttrsStr));
			sbSf.insert(0, CRLF);
			sbSf.insert(0, createAttributeText(CREATED_BY_ATTR, signer));
			sbSf.insert(0, CRLF);
			sbSf.insert(0, createAttributeText(SIGNATURE_VERSION_ATTR, SIGNATURE_VERSION));

			// Signature file complete
			byte[] sf = sbSf.toString().getBytes();

			// Create output stream to write signed JAR
			jos = new JarOutputStream(new FileOutputStream(signedJarFile));

			// Write JAR files from JAR to be signed to signed JAR
			writeJarEntries(jar, jos, signatureName);

			// Write manifest to signed JAR
			writeManifest(manifest, jos);

			// Write signature file to signed JAR
			writeSignatureFile(sf, signatureName, jos);

			// Create signature block and write it out to signed JAR
			byte[] sigBlock = createSignatureBlock(sf, privateKey, certificateChain, signatureType, provider);
			writeSignatureBlock(sigBlock, signatureType, signatureName, jos);
		} finally {
			SafeCloseUtil.close(jar);
			SafeCloseUtil.close(jos);
		}
	}

	private static boolean ignoreJarEntry(JarEntry jarEntry) {
		/*
		 * Ignore a JAR entry for signing? JAR entries which should not be
		 * signed are the manifest files, signature files and signature block
		 * files
		 */

		String entryName = jarEntry.getName();

		// Entries to be ignored are all in the "META-INF" folder
		if (entryName.startsWith("META-INF/")) {
			if (entryName.toUpperCase().equals(MANIFEST_LOCATION)) {
				return true; // Manifest file - ignore
			}

			if (entryName.toUpperCase().endsWith(SIGNATURE_EXT)) {
				return true; // Signature file - ignore
			}

			if (entryName.toUpperCase().endsWith(RSA_SIG_BLOCK_EXT)) {
				return true; // RSA signature block file - ignore
			}

			if (entryName.toUpperCase().endsWith(DSA_SIG_BLOCK_EXT)) {
				return true; // DSA signature block file - ignore
			}
		}

		return false;
	}

	/**
	 * Does the named signature already exist in the JAR file?
	 *
	 * @param jarFile
	 *            JAR file
	 * @param signatureName
	 *            Signature name
	 * @return True if it does, false otherwise
	 * @throws IOException
	 *             If an I/O problem occurs while examining the JAR file
	 */
	public static boolean hasSignature(File jarFile, String signatureName) throws IOException {
		JarFile jar = null;

		try {
			// Look for signature file (DSA or RSA)
			jar = new JarFile(jarFile);

			for (Enumeration jarEntries = jar.entries(); jarEntries.hasMoreElements();) {
				JarEntry jarEntry = (JarEntry) jarEntries.nextElement();
				if (!jarEntry.isDirectory()) {
					if ((jarEntry.getName().equalsIgnoreCase(MessageFormat.format(METAINF_FILE_LOCATION, signatureName,
							DSA_SIG_BLOCK_EXT)))
							|| (jarEntry.getName().equalsIgnoreCase(MessageFormat.format(METAINF_FILE_LOCATION,
									signatureName, RSA_SIG_BLOCK_EXT)))) {
						return true;
					}
				}
			}

			return false;
		} finally {
			SafeCloseUtil.close(jar);
		}
	}

	private static String getManifestMainAttrs(JarFile jar, String signer) throws IOException {
		/*
		 * Get main attributes of JAR manifest as a string. Gets original
		 * manifest verbatim. If there is no manifest in JAR it returns a string
		 * with those two attributes
		 */

		StringBuffer sbManifest = new StringBuffer();

		// Get current manifest
		Manifest manifest = jar.getManifest();

		// Write out main attributes to manifest

		if (manifest == null) {
			// No current manifest - write out main attributes
			// ("Manifest Version" and "Created By")
			sbManifest.append(createAttributeText(MANIFEST_VERSION_ATTR, MANIFEST_VERSION));
			sbManifest.append(CRLF);

			sbManifest.append(createAttributeText(CREATED_BY_ATTR, signer));
			sbManifest.append(CRLF);

			sbManifest.append(CRLF);
		} else {
			// Get main attributes as a string to preserve their order
			String manifestMainAttrs = getManifestMainAttrs(jar);

			// Write them out
			sbManifest.append(manifestMainAttrs);
			sbManifest.append(CRLF);
		}

		return sbManifest.toString();
	}

	private static String getManifestEntriesAttrs(JarFile jar) throws IOException {
		// Get all entries' attributes of JAR manifest as a string

		StringBuffer sbManifest = new StringBuffer();

		// Get current manifest
		Manifest manifest = jar.getManifest();

		// Write out entry attributes to manifest
		if (manifest != null) {
			// Get entry attributes
			Map<String, Attributes> entries = manifest.getEntries();

			boolean firstEntry = true;

			// For each entry...
			entry: for (String entryName : entries.keySet()) {
				// Get entry's attributes
				Attributes entryAttrs = entries.get(entryName);

				// Completely ignore entries that contain only a xxx-Digest
				// attribute
				if ((entryAttrs.size() == 1)
						&& (((Attributes.Name) entryAttrs.keySet().toArray()[0]).toString().endsWith("-Digest"))) {
					continue entry;
				}

				if (!firstEntry) {
					// Entries subequent to the first are split by a newline
					sbManifest.append(CRLF);
				}

				// Get entry attributes as a string to preserve their order
				String manifestEntryAttributes = getManifestEntryAttrs(jar, entryName);

				// Write them out
				sbManifest.append(manifestEntryAttributes);

				// The next entry will not be the first entry
				firstEntry = false;
			}
		}

		return sbManifest.toString();
	}

	private static String getDigestManifestAttrs(JarFile jar, JarEntry jarEntry, DigestType digestType)
			throws IOException, CryptoException {
		// Get the digest of the supplied JAR entry as manifest attributes
		// "Name" and
		// "<digestType> Digest"

		InputStream jis = null;

		try {
			// Get input stream to JAR entry's content
			jis = jar.getInputStream(jarEntry);

			// Get the digest of content in Base64
			byte[] md = DigestUtil.getMessageDigest(jis, digestType);
			byte[] md64 = Base64.encode(md);
			String md64Str = new String(md64);

			// Write manifest entries for JARs digest
			StringBuffer sbManifestEntry = new StringBuffer();
			sbManifestEntry.append(createAttributeText(NAME_ATTR, jarEntry.getName()));
			sbManifestEntry.append(CRLF);
			sbManifestEntry.append(createAttributeText(MessageFormat.format(DIGEST_ATTR, digestType.jce()), md64Str));
			sbManifestEntry.append(CRLF);
			sbManifestEntry.append(CRLF);

			return sbManifestEntry.toString();
		} finally {
			SafeCloseUtil.close(jis);
		}
	}

	private static String getManifest(JarFile jar) throws IOException {
		// Get JAR file's manifest as a string

		JarEntry manifestEntry = jar.getJarEntry(MANIFEST_LOCATION);

		InputStream jis = null;
		ByteArrayOutputStream baos = null;

		try {
			jis = jar.getInputStream(manifestEntry);
			baos = new ByteArrayOutputStream();

			CopyUtil.copyClose(jis, baos);
			baos.close();

			String manifest = baos.toString();

			return manifest;
		} finally {
			SafeCloseUtil.close(jis);
			SafeCloseUtil.close(baos);
		}
	}

	private static String getManifestMainAttrs(JarFile jar) throws IOException {
		// Get JAR file manifest's main attributes manifest as a string

		// Get full manifest content
		String manifestContent = getManifest(jar);

		LineNumberReader lnr = new LineNumberReader(new StringReader(manifestContent));

		try {
			StringBuffer sb = new StringBuffer();

			String line = null;

			// Keep reading until a blank line is found - the end of the main
			// attributes
			while ((line = lnr.readLine()) != null) {
				if (line.trim().length() == 0) {
					break;
				}

				// Append attribute line
				sb.append(line);
				sb.append(CRLF);
			}

			return sb.toString();
		} finally {
			SafeCloseUtil.close(lnr);
		}
	}

	private static String getManifestEntryAttrs(JarFile jar, String entryName) throws IOException {
		// Get JAR file manifest's attributes for a specified entry as a string

		// Get full manifest content
		String manifestContent = getManifest(jar);

		LineNumberReader lnr = new LineNumberReader(new StringReader(manifestContent));

		try {
			StringBuffer sb = new StringBuffer();

			String line = null;

			// First entry name attribute to match
			String entryNameAttr = createAttributeText(NAME_ATTR, entryName);

			// Only match on first 70 characters (max line length)
			if (entryNameAttr.length() > 70) {
				entryNameAttr = entryNameAttr.substring(0, 70);
			}

			/*
			 * Keep reading and ignoring lines until entry is found - the end of
			 * the entry's attributes
			 */
			while ((line = lnr.readLine()) != null) {
				if (line.equals(entryNameAttr)) {
					// Found entry name attribute - append it
					sb.append(line);
					sb.append(CRLF);
					break;
				}
			}

			// Keep reading until a blank line is found - the end of the entry's
			// attributes
			while ((line = lnr.readLine()) != null) {
				if (line.trim().length() == 0) {
					break;
				}

				// Append another entry attribute line
				sb.append(line);
				sb.append(CRLF);
			}

			return sb.toString();
		} finally {
			SafeCloseUtil.close(lnr);
		}
	}

	private static void writeJarEntries(JarFile jar, JarOutputStream jos, String signatureName) throws IOException {
		/*
		 * Write out all JAR entries from source JAR to output stream excepting
		 * manifest and existing signature files for the supplied signature name
		 */

		for (Enumeration jarEntries = jar.entries(); jarEntries.hasMoreElements();) {
			JarEntry jarEntry = (JarEntry) jarEntries.nextElement();
			if (!jarEntry.isDirectory()) {
				String entryName = jarEntry.getName();

				// Signature files not to write across
				String sigFileLocation = MessageFormat.format(METAINF_FILE_LOCATION, signatureName, SIGNATURE_EXT)
						.toUpperCase();
				String dsaSigBlockLocation = MessageFormat.format(METAINF_FILE_LOCATION, signatureName,
						DSA_SIG_BLOCK_EXT);
				String rsaSigBlockLocation = MessageFormat.format(METAINF_FILE_LOCATION, signatureName,
						RSA_SIG_BLOCK_EXT);

				// Do not write across existing manifest or matching signature
				// files
				if ((!entryName.equalsIgnoreCase(MANIFEST_LOCATION)) && (!entryName.equalsIgnoreCase(sigFileLocation))
						&& (!entryName.equalsIgnoreCase(dsaSigBlockLocation))
						&& (!entryName.equalsIgnoreCase(rsaSigBlockLocation))) {
					// New JAR entry based on original
					JarEntry newJarEntry = new JarEntry(jarEntry.getName());
					newJarEntry.setMethod(jarEntry.getMethod());
					newJarEntry.setCompressedSize(jarEntry.getCompressedSize());
					newJarEntry.setCrc(jarEntry.getCrc());
					jos.putNextEntry(newJarEntry);

					InputStream jis = null;

					try {
						jis = jar.getInputStream(jarEntry);

						byte[] buffer = new byte[2048];
						int read = -1;

						while ((read = jis.read(buffer)) != -1) {
							jos.write(buffer, 0, read);
						}

						jos.closeEntry();
					} finally {
						SafeCloseUtil.close(jis);
					}
				}
			}
		}
	}

	private static void writeManifest(byte[] manifest, JarOutputStream jos) throws IOException {
		// Write manifest content to output stream

		// Manifest file entry
		JarEntry mfJarEntry = new JarEntry(MANIFEST_LOCATION);
		jos.putNextEntry(mfJarEntry);

		// Write content
		ByteArrayInputStream bais = null;

		try {
			bais = new ByteArrayInputStream(manifest);

			byte[] buffer = new byte[2048];
			int read = -1;

			while ((read = bais.read(buffer)) != -1) {
				jos.write(buffer, 0, read);
			}

			jos.closeEntry();
		} finally {
			SafeCloseUtil.close(bais);
		}
	}

	private static void writeSignatureFile(byte[] sf, String signatureName, JarOutputStream jos) throws IOException {
		// Write signature file content to output stream

		// Signature file entry
		JarEntry sfJarEntry = new JarEntry(MessageFormat.format(METAINF_FILE_LOCATION, signatureName, SIGNATURE_EXT)
				.toUpperCase());
		jos.putNextEntry(sfJarEntry);

		// Write content
		ByteArrayInputStream bais = null;

		try {
			bais = new ByteArrayInputStream(sf);

			byte[] buffer = new byte[2048];
			int read = -1;

			while ((read = bais.read(buffer)) != -1) {
				jos.write(buffer, 0, read);
			}

			jos.closeEntry();
		} finally {
			SafeCloseUtil.close(bais);
		}
	}

	private static void writeSignatureBlock(byte[] sigBlock, SignatureType signatureType, String signatureName,
			JarOutputStream jos) throws IOException {
		// Write signature block to output stream

		// Block's extension depends on signature type
		String extension = null;

		if (signatureType == SHA1_DSA) {
			extension = DSA_SIG_BLOCK_EXT;
		} else {
			extension = RSA_SIG_BLOCK_EXT;
		}

		// Signature block entry
		JarEntry bkJarEntry = new JarEntry(MessageFormat.format(METAINF_FILE_LOCATION, signatureName, extension)
				.toUpperCase());
		jos.putNextEntry(bkJarEntry);

		// Write content
		ByteArrayInputStream bais = new ByteArrayInputStream(sigBlock);

		byte[] buffer = new byte[2048];
		int read = -1;

		while ((read = bais.read(buffer)) != -1) {
			jos.write(buffer, 0, read);
		}

		jos.closeEntry();
	}

	private static String createAttributeText(String attributeName, String attributeValue) {
		// Create manifest attribute text from the supplied attribute name and
		// value

		String attributeText = MessageFormat.format(ATTR_TEMPLATE, attributeName, attributeValue);

		/*
		 * No attribute text can have lines exceeding 72 bytes. Split it across
		 * lines no greater than 72 bytes by inserting '\r\n '
		 */
		StringBuffer sb = new StringBuffer();

		// Remaining text to split
		String remainingText = attributeText;

		while (true) {
			if (remainingText.length() > 70) {
				// Split a line
				sb.append(remainingText.substring(0, 70));
				sb.append(CRLF);
				sb.append(" ");
				remainingText = remainingText.substring(70);
			} else {
				// Done splitting
				sb.append(remainingText);
				break;
			}
		}

		return sb.toString();
	}

	private static byte[] createSignatureBlock(byte[] toSign, PrivateKey privateKey,
			X509Certificate[] certificateChain, SignatureType signatureType, Provider provider) throws CryptoException {

		ByteArrayInputStream bais = null;

		try {
			List<X509Certificate> certList = new ArrayList<X509Certificate>();

			for (int i = 0; i < certificateChain.length; i++) {
				certList.add(certificateChain[i]);
			}

			DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
            JcaSignerInfoGeneratorBuilder siGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digCalcProv);

            JcaContentSignerBuilder csb = new JcaContentSignerBuilder(signatureType.jce())
		                                            .setSecureRandom(SecureRandom.getInstance("SHA1PRNG"));
            if (provider == null)  {
                    csb.setProvider(provider);
            }

			CMSSignedDataGenerator dataGen = new CMSSignedDataGenerator();
			dataGen.addSignerInfoGenerator(siGeneratorBuilder.build(csb.build(privateKey), certificateChain[0]));
			dataGen.addCertificates(new JcaCertStore(certList));

			CMSSignedData signed = dataGen.generate(new CMSProcessableByteArray(toSign), true);

			return signed.getEncoded();
		} catch (IOException ex) {
			throw new CryptoException(res.getString("SignatureBlockCreationFailed.exception.message"), ex);
		} catch (CMSException ex) {
			throw new CryptoException(res.getString("SignatureBlockCreationFailed.exception.message"), ex);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("SignatureBlockCreationFailed.exception.message"), ex);
		} catch (OperatorCreationException ex) {
			throw new CryptoException(res.getString("SignatureBlockCreationFailed.exception.message"), ex);
		} finally {
			SafeCloseUtil.close(bais);
		}
	}

	private static String convertSignatureName(String signatureName) {
		/*
		 * Convert the supplied signature name to make it valid for use with
		 * signing, ie any characters that are not 'a-z', 'A-Z', '0-9', '_' or
		 * '-' are converted to '_'
		 */

		StringBuffer sb = new StringBuffer(signatureName.length());

		for (int i = 0; i < signatureName.length(); i++) {
			char c = signatureName.charAt(i);

			if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_') {
				c = '_';
			}
			sb.append(c);
		}

		return sb.toString();
	}
}
