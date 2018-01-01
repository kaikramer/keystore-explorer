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
package org.kse.crypto.x509;

import static org.kse.crypto.SecurityProvider.BOUNCY_CASTLE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.util.encoders.Base64;
import org.kse.crypto.CryptoException;
import org.kse.crypto.signing.SignatureType;
import org.kse.utilities.ArrayUtils;
import org.kse.utilities.io.IOUtils;
import org.kse.utilities.io.ReadUtil;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

/**
 * Provides utility methods relating to X509 Certificates and CRLs.
 *
 */
public final class X509CertUtil {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
	private static final String X509_CERT_TYPE = "X.509";
	private static final String PKCS7_ENCODING = "PKCS7";
	private static final String PKI_PATH_ENCODING = "PkiPath";
	private static final String CERT_PEM_TYPE = "CERTIFICATE";
	private static final String PKCS7_PEM_TYPE = "PKCS7";

	public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
	public static final String BASE64_TESTER = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";

	private X509CertUtil() {
	}

	/**
	 * Load one or more certificates from the specified stream.
	 *
	 * @param is
	 *            Stream to load certificates from
	 * @return The certificates
	 * @throws CryptoException
	 *             Problem encountered while loading the certificate(s)
	 */
	public static X509Certificate[] loadCertificates(InputStream is) throws CryptoException {
		byte[] certsBytes = null;

		try {
			certsBytes = ReadUtil.readFully(is);

			// fix common input certificate problems by converting PEM/B64 to DER
			certsBytes = fixCommonInputCertProblems(certsBytes);

			is = new ByteArrayInputStream(certsBytes);

			CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, BOUNCY_CASTLE.jce());

			Collection<? extends Certificate> certs = cf.generateCertificates(is);

			ArrayList<X509Certificate> loadedCerts = new ArrayList<X509Certificate>();

			for (Iterator<? extends Certificate> itr = certs.iterator(); itr.hasNext();) {
				X509Certificate cert = (X509Certificate) itr.next();

				if (cert != null) {
					loadedCerts.add(cert);
				}
			}

			return loadedCerts.toArray(new X509Certificate[loadedCerts.size()]);
		} catch (IOException | NoSuchProviderException ex) {
			throw new CryptoException(res.getString("NoLoadCertificate.exception.message"), ex);
		} catch (CertificateException ex) {
			// Failed to load certificates, may be pki path encoded - try loading as that
			try {
				return loadCertificatesPkiPath(new ByteArrayInputStream(certsBytes));
			} catch (CryptoException ex2) {
				throw new CryptoException(res.getString("NoLoadCertificate.exception.message"), ex);
			}
		} finally {
			IOUtils.closeQuietly(is);
		}
	}

	private static X509Certificate[] loadCertificatesPkiPath(InputStream is) throws CryptoException {
		try {
			CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, BOUNCY_CASTLE.jce());
			CertPath certPath = cf.generateCertPath(is, PKI_PATH_ENCODING);

			List<? extends Certificate> certs = certPath.getCertificates();

			ArrayList<X509Certificate> loadedCerts = new ArrayList<X509Certificate>();

			for (Iterator<? extends Certificate> itr = certs.iterator(); itr.hasNext();) {
				X509Certificate cert = (X509Certificate) itr.next();

				if (cert != null) {
					loadedCerts.add(cert);
				}
			}

			return loadedCerts.toArray(new X509Certificate[loadedCerts.size()]);
		} catch (CertificateException | NoSuchProviderException e) {
			throw new CryptoException(res.getString("NoLoadPkiPath.exception.message"), e);
		} finally {
			IOUtils.closeQuietly(is);
		}
	}

	private static byte[] fixCommonInputCertProblems(byte[] certs) throws IOException {

		// remove PEM header/footer
		String certsStr = new String(certs);
		if (certsStr.startsWith(BEGIN_CERTIFICATE)) {
			certsStr = certsStr.replaceAll(BEGIN_CERTIFICATE, "");
			certsStr = certsStr.replaceAll(END_CERTIFICATE, "!");
		}

		// If one or more base 64 encoded certs then decode
		String[] splitCertsStr = certsStr.split("!");
		byte[] allDecoded = null;
		for (String singleCertB64 : splitCertsStr) {
			byte[] decoded = attemptBase64Decode(singleCertB64.trim());
			if (decoded != null) {
				allDecoded = ArrayUtils.add(allDecoded, decoded);
			}
		}
		if (allDecoded != null) {
			return allDecoded;
		}

		return certs;
	}

	private static byte[] attemptBase64Decode(String toTest) {

		// Attempt to decode the supplied byte array as a base 64 encoded SPC.
		// Character set may be UTF-16 big endian or ASCII.

		char[] base64 = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
				'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
				'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
				'6', '7', '8', '9', '+', '/', '=' };

		// remove all non visible characters (like newlines) and whitespace
		toTest = toTest.replaceAll("\\s", "");

		// Check all characters are base 64. Discard any zero bytes that be
		// present if UTF-16 encoding is used but will mess up a base 64 decode
		StringBuffer sb = new StringBuffer();

		nextChar: for (int i = 0; i < toTest.length(); i++) {
			char c = toTest.charAt(i);

			for (int j = 0; j < base64.length; j++) {
				// append base 64 byte
				if (c == base64[j]) {
					sb.append(c);
					continue nextChar;
				} else if (c == 0) {
					// discard zero byte
					continue nextChar;
				}
			}

			// not base 64
			return null;
		}

		// use BC for actual decoding
		try {
			return Base64.decode(sb.toString());
		} catch (Exception e) {
			// not base 64
		}

		return null;
	}



	/**
	 * Load a CRL from the specified stream.
	 *
	 * @param is
	 *            Stream to load CRL from
	 * @return The CRL
	 * @throws CryptoException
	 *             Problem encountered while loading the CRL
	 */
	public static X509CRL loadCRL(InputStream is) throws CryptoException {
		try {
			CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE);
			X509CRL crl = (X509CRL) cf.generateCRL(is);
			return crl;
		} catch (CertificateException ex) {
			throw new CryptoException(res.getString("NoLoadCrl.exception.message"), ex);
		} catch (CRLException ex) {
			throw new CryptoException(res.getString("NoLoadCrl.exception.message"), ex);
		} finally {
			IOUtils.closeQuietly(is);
		}
	}

	/**
	 * Convert the supplied array of certificate objects into X509Certificate
	 * objects.
	 *
	 * @param certsIn
	 *            The Certificate objects
	 * @return The converted X509Certificate objects
	 * @throws CryptoException
	 *             A problem occurred during the conversion
	 */
	public static X509Certificate[] convertCertificates(Certificate[] certsIn) throws CryptoException {

		if (certsIn == null) {
			return new X509Certificate[0];
		}

		X509Certificate[] certsOut = new X509Certificate[certsIn.length];

		for (int i = 0; i < certsIn.length; i++) {
			certsOut[i] = convertCertificate(certsIn[i]);
		}

		return certsOut;
	}

	/**
	 * Convert the supplied certificate object into an X509Certificate object.
	 *
	 * @param certIn
	 *            The Certificate object
	 * @return The converted X509Certificate object
	 * @throws CryptoException
	 *             A problem occurred during the conversion
	 */
	public static X509Certificate convertCertificate(Certificate certIn) throws CryptoException {
		try {
			CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, BOUNCY_CASTLE.jce());
			ByteArrayInputStream bais = new ByteArrayInputStream(certIn.getEncoded());
			return (X509Certificate) cf.generateCertificate(bais);
		} catch (CertificateException | NoSuchProviderException e) {
			throw new CryptoException(res.getString("NoConvertCertificate.exception.message"), e);
		}
	}

	/**
	 * Order the supplied array of X.509 certificates in issued to issuer order.
	 *
	 * @param certs
	 *            X.509 certificates
	 * @return The ordered X.509 certificates
	 */
	public static X509Certificate[] orderX509CertChain(X509Certificate certs[]) {

		if (certs == null) {
			return new X509Certificate[0];
		}

		if (certs.length <= 1) {
			return certs;
		}

		// Put together each possible certificate path...
		ArrayList<ArrayList<X509Certificate>> paths = new ArrayList<ArrayList<X509Certificate>>();

		// For each possible path...
		for (int i = 0; i < certs.length; i++) {
			// Each possible path assumes a different certificate is the root issuer
			ArrayList<X509Certificate> path = new ArrayList<X509Certificate>();
			X509Certificate issuerCert = certs[i];
			path.add(issuerCert);

			X509Certificate newIssuer = null;

			// Recursively build that path by finding the next issued certificate
			while ((newIssuer = findIssuedCert(issuerCert, certs)) != null) {
				// Found an issued cert, now attempt to find its issued certificate
				issuerCert = newIssuer;
				path.add(0, newIssuer);
			}

			// Path complete
			paths.add(path);
		}

		// Get longest path - this will be the ordered path
		ArrayList<X509Certificate> longestPath = paths.get(0);
		for (int i = 1; i < paths.size(); i++) {
			ArrayList<X509Certificate> path = paths.get(i);
			if (path.size() > longestPath.size()) {
				longestPath = path;
			}
		}

		// Return longest path
		return longestPath.toArray(new X509Certificate[longestPath.size()]);
	}

	private static X509Certificate findIssuedCert(X509Certificate issuerCert, X509Certificate[] certs) {
		// Find a certificate issued by the supplied certificate based on  distiguished name
		for (int i = 0; i < certs.length; i++) {
			X509Certificate cert = certs[i];

			if (issuerCert.getSubjectX500Principal().equals(cert.getSubjectX500Principal())
					&& issuerCert.getIssuerX500Principal().equals(cert.getIssuerX500Principal())) {
				// Checked certificate is issuer - ignore it
				continue;
			}

			if (issuerCert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
				return cert;
			}
		}

		return null;
	}

	/**
	 * X.509 encode a certificate.
	 *
	 * @return The encoding
	 * @param cert
	 *            The certificate
	 * @throws CryptoException
	 *             If there was a problem encoding the certificate
	 */
	public static byte[] getCertEncodedX509(X509Certificate cert) throws CryptoException {
		try {
			return cert.getEncoded();
		} catch (CertificateException ex) {
			throw new CryptoException(res.getString("NoDerEncodeCertificate.exception.message"), ex);
		}
	}

	/**
	 * X.509 encode a certificate and PEM the encoding.
	 *
	 * @return The PEM'd encoding
	 * @param cert
	 *            The certificate
	 * @throws CryptoException
	 *             If there was a problem encoding the certificate
	 */
	public static String getCertEncodedX509Pem(X509Certificate cert) throws CryptoException {
		PemInfo pemInfo = new PemInfo(CERT_PEM_TYPE, null, getCertEncodedX509(cert));
		return PemUtil.encode(pemInfo);
	}

	/**
	 * X.509 encode a number of certificates and PEM the encoding.
	 *
	 * @return The PEM'd encoding
	 * @param cert
	 *            The certificates
	 * @throws CryptoException
	 *             If there was a problem encoding the certificates
	 */
	public static String getCertsEncodedX509Pem(X509Certificate[] certs) throws CryptoException {
		StringBuilder sb = new StringBuilder();
		for (X509Certificate cert : certs) {
			sb.append(getCertEncodedX509Pem(cert));
		}
		return sb.toString();
	}

	/**
	 * PKCS #7 encode a certificate.
	 *
	 * @return The encoding
	 * @param cert
	 *            The certificate
	 * @throws CryptoException
	 *             If there was a problem encoding the certificate
	 */
	public static byte[] getCertEncodedPkcs7(X509Certificate cert) throws CryptoException {
		return getCertsEncodedPkcs7(new X509Certificate[] { cert });
	}

	/**
	 * PKCS #7 encode a number of certificates.
	 *
	 * @return The encoding
	 * @param certs
	 *            The certificates
	 * @throws CryptoException
	 *             If there was a problem encoding the certificates
	 */
	public static byte[] getCertsEncodedPkcs7(X509Certificate[] certs) throws CryptoException {
		try {
			ArrayList<Certificate> encodedCerts = new ArrayList<Certificate>();

			Collections.addAll(encodedCerts, certs);

			CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, BOUNCY_CASTLE.jce());

			CertPath cp = cf.generateCertPath(encodedCerts);

			return cp.getEncoded(PKCS7_ENCODING);
		} catch (CertificateException | NoSuchProviderException e) {
			throw new CryptoException(res.getString("NoPkcs7Encode.exception.message"), e);
		}
	}

	/**
	 * PKCS #7 encode a certificate and PEM the encoding.
	 *
	 * @param cert
	 *            The certificate
	 * @return The PEM'd encoding
	 * @throws CryptoException
	 *             If there was a problem encoding the certificate
	 */
	public static String getCertEncodedPkcs7Pem(X509Certificate cert) throws CryptoException {
		return getCertsEncodedPkcs7Pem(new X509Certificate[] { cert });
	}

	/**
	 * PKCS #7 encode a number of certificates and PEM the encoding.
	 *
	 * @param certs
	 *            The certificates
	 * @return The PEM'd encoding
	 * @throws CryptoException
	 *             If there was a problem encoding the certificates
	 */
	public static String getCertsEncodedPkcs7Pem(X509Certificate[] certs) throws CryptoException {
		PemInfo pemInfo = new PemInfo(PKCS7_PEM_TYPE, null, getCertsEncodedPkcs7(certs));
		return PemUtil.encode(pemInfo);
	}

	/**
	 * PKI Path encode a certificate.
	 *
	 * @return The encoding
	 * @param cert
	 *            The certificate
	 * @throws CryptoException
	 *             If there was a problem encoding the certificate
	 */
	public static byte[] getCertEncodedPkiPath(X509Certificate cert) throws CryptoException {
		return getCertsEncodedPkiPath(new X509Certificate[] { cert });
	}

	/**
	 * PKI Path encode a number of certificates.
	 *
	 * @return The encoding
	 * @param certs
	 *            The certificates
	 * @throws CryptoException
	 *             If there was a problem encoding the certificates
	 */
	public static byte[] getCertsEncodedPkiPath(X509Certificate[] certs) throws CryptoException {
		try {
			ArrayList<Certificate> encodedCerts = new ArrayList<Certificate>();

			Collections.addAll(encodedCerts, certs);

			CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, BOUNCY_CASTLE.jce());

			CertPath cp = cf.generateCertPath(encodedCerts);

			return cp.getEncoded(PKI_PATH_ENCODING);
		} catch (CertificateException | NoSuchProviderException e) {
			throw new CryptoException(res.getString("NoPkcs7Encode.exception.message"), e);
		}
	}

	/**
	 * Verify that one X.509 certificate was signed using the private key that
	 * corresponds to the public key of a second certificate.
	 *
	 * @return True if the first certificate was signed by private key
	 *         corresponding to the second signature
	 * @param signedCert
	 *            The signed certificate
	 * @param signingCert
	 *            The signing certificate
	 * @throws CryptoException
	 *             If there was a problem verifying the signature.
	 */
	public static boolean verifyCertificate(X509Certificate signedCert, X509Certificate signingCert)
			throws CryptoException {
		try {
			signedCert.verify(signingCert.getPublicKey());
			return true;
		}
		// Verification failed
		catch (InvalidKeyException ex) {
			return false;
		} catch (SignatureException ex) {
			return false;
		}
		// Problem verifying
		catch (NoSuchProviderException ex) {
			throw new CryptoException(res.getString("NoVerifyCertificate.exception.message"), ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(res.getString("NoVerifyCertificate.exception.message"), ex);
		} catch (CertificateException ex) {
			throw new CryptoException(res.getString("NoVerifyCertificate.exception.message"), ex);
		}
	}

	/**
	 * Check whether or not a trust path exists between the supplied X.509
	 * certificate and and the supplied keystores based on the trusted
	 * certificates contained therein, ie that a chain of trust exists between
	 * the supplied certificate and a self-signed trusted certificate in the
	 * KeyStores.
	 *
	 * @return The trust chain, or null if trust could not be established
	 * @param cert
	 *            The certificate
	 * @param keyStores
	 *            The KeyStores
	 * @throws CryptoException
	 *             If there is a problem establishing trust
	 */
	public static X509Certificate[] establishTrust(X509Certificate cert, KeyStore keyStores[]) throws CryptoException {
		ArrayList<X509Certificate> ksCerts = new ArrayList<X509Certificate>();

		for (int i = 0; i < keyStores.length; i++) {
			ksCerts.addAll(extractCertificates(keyStores[i]));
		}

		return establishTrust(cert, ksCerts);
	}

	private static X509Certificate[] establishTrust(X509Certificate cert, List<X509Certificate> compCerts)
			throws CryptoException {
		/*
		 * Check whether or not a trust path exists between the supplied X.509
		 * certificate and and the supplied comparison certificates , ie that a
		 * chain of trust exists between the certificate and a self-signed
		 * trusted certificate in the comparison set
		 */

		for (int i = 0; i < compCerts.size(); i++) {
			X509Certificate compCert = compCerts.get(i);

			// Verify of certificate issuer is sam as comparison certificate's subject
			if (cert.getIssuerX500Principal().equals(compCert.getSubjectX500Principal())) {
				// Verify if the comparison certificate's private key was used to sign the certificate
				if (X509CertUtil.verifyCertificate(cert, compCert)) {
					// If the comparision certificate is self-signed then a chain of trust exists
					if (compCert.getSubjectX500Principal().equals(compCert.getIssuerX500Principal())) {
						return new X509Certificate[] { cert, compCert };
					}

					/*
					 * Otherwise try and establish a chain of trust from the
					 * comparison certificate against the other comparison certificates
					 */
					X509Certificate[] tmpChain = establishTrust(compCert, compCerts);
					if (tmpChain != null) {
						X509Certificate[] trustChain = new X509Certificate[tmpChain.length + 1];

						trustChain[0] = cert;

						System.arraycopy(tmpChain, 0, trustChain, 1, tmpChain.length);

						return trustChain;
					}
				}
			}
		}

		return null; // No chain of trust
	}

	private static List<X509Certificate> extractCertificates(KeyStore keyStore) throws CryptoException {
		try {
			List<X509Certificate> certs = new ArrayList<X509Certificate>();

			for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();) {
				String alias = aliases.nextElement();

				if (keyStore.isCertificateEntry(alias)) {
					certs.add(X509CertUtil.convertCertificate(keyStore.getCertificate(alias)));
				}
			}

			return certs;
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("NoExtractCertificates.exception.message"), ex);
		}
	}

	/**
	 * Check whether or not a trusted certificate in the supplied KeyStore
	 * matches the supplied X.509 certificate.
	 *
	 * @param cert
	 *            The certificate
	 * @param keyStore
	 *            The KeyStore
	 * @return The alias of the matching certificate in the KeyStore or null if
	 *         there is no match
	 * @throws CryptoException
	 *             If there is a problem establishing trust
	 */
	public static String matchCertificate(KeyStore keyStore, X509Certificate cert) throws CryptoException {
		try {
			for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();) {
				String alias = aliases.nextElement();
				if (keyStore.isCertificateEntry(alias)) {
					X509Certificate compCert = X509CertUtil.convertCertificate(keyStore.getCertificate(alias));

					if (cert.equals(compCert)) {
						return alias;
					}
				}
			}
			return null;
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("NoMatchCertificate.exception.message"), ex);
		}
	}

	/**
	 * For a given X.509 certificate get a representative alias for it in a
	 * KeyStore. For a self-signed certificate this will be the subject's common
	 * name (if any). For a non-self-signed certificate it will be the subject's
	 * common name followed by the issuer's common name in brackets. Aliases
	 * will always be in lower case.
	 *
	 * @param cert
	 *            The certificate
	 * @return The alias or a blank string if none could be worked out
	 */
	public static String getCertificateAlias(X509Certificate cert) {
		X500Principal subject = cert.getSubjectX500Principal();
		X500Principal issuer = cert.getIssuerX500Principal();

		String subjectCn = extractCommonName(X500NameUtils.x500PrincipalToX500Name(subject));
		String issuerCn = extractCommonName(X500NameUtils.x500PrincipalToX500Name(issuer));

		if (subjectCn == null) {
			return "";
		}

		if (issuerCn == null || subjectCn.equals(issuerCn)) {
			return subjectCn;
		}

		return MessageFormat.format("{0} ({1})", subjectCn, issuerCn);
	}

	private static String extractCommonName(X500Name name) {
		for (RDN rdn : name.getRDNs()) {
			AttributeTypeAndValue atav = rdn.getFirst();

			if (atav.getType().equals(BCStyle.CN)) {
				return atav.getValue().toString();
			}
		}

		return null;
	}

	/**
	 * Get short name for certificate. Common name if available, otherwise use
	 * entire distinguished name.
	 *
	 * @param cert
	 *            Certificate
	 * @return Short name
	 */
	public static String getShortName(X509Certificate cert) {
		X500Name subject = X500NameUtils.x500PrincipalToX500Name(cert.getSubjectX500Principal());

		String shortName = extractCommonName(subject);

		if (shortName == null) {
			shortName = subject.toString();
		}

		return shortName;
	}

	/**
	 * For a given X.509 certificate get the algorithm of its signature. Useful
	 * as the JCE may return an unfriendly name. This method converts known
	 * "unfriendly names" to friendly names.
	 *
	 * @param cert
	 *            The certificate
	 * @return The algorithm
	 */
	public static String getCertificateSignatureAlgorithm(X509Certificate cert) {
		// Unfriendly JCE sig names may be actual JCE names or OIDs
		String algorithm = cert.getSigAlgName();

		SignatureType type = SignatureType.resolveJce(algorithm);

		if (type != null) {
			algorithm = type.friendly();
		} else {
			type = SignatureType.resolveOid(algorithm);

			if (type != null) {
				algorithm = type.friendly();
			}
		}

		return algorithm;
	}

	/**
	 * Is the supplied X.509 certificate self-signed?
	 *
	 * @param cert
	 *            The certificate
	 * @return True if it is
	 */
	public static boolean isCertificateSelfSigned(X509Certificate cert) {
		return cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
	}

}
