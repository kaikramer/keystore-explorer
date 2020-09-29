/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
package org.kse.crypto.csr.pkcs10;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_challengePassword;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.ResourceBundle;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.kse.crypto.CryptoException;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X509ExtensionSet;

/**
 * Provides utility methods relating to PKCS #10 CSRs.
 *
 */
public class Pkcs10Util {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/csr/pkcs10/resources");
	private static final String BEGIN_CSR_FORM_1 = "-----BEGIN CERTIFICATE REQUEST-----";
	private static final String END_CSR_FORM_1 = "-----END CERTIFICATE REQUEST-----";
	private static final String BEGIN_CSR_FORM_2 = "-----BEGIN NEW CERTIFICATE REQUEST-----";
	private static final String END_CSR_FORM_2 = "-----END NEW CERTIFICATE REQUEST-----";
	private static final int MAX_PRINTABLE_ENC_LINE_LENGTH = 76;

	private Pkcs10Util() {
	}

	/**
	 * Create a PKCS #10 certificate signing request (CSR) using the supplied
	 * certificate, private key and signature algorithm.
	 *
	 * @param subjectDN Distinguished name for CSR
	 * @param publicKey Public key for CSR
	 * @param privateKey Private key for CSR
	 * @param signatureType Signature algorithm
	 * @param challenge Challenge, optional, pass null if not required
	 * @param unstructuredName An optional company name, pass null if not required
	 * @param extensions Optional extensions from cert for extensionRequest attribute, pass null if not required
	 * @param provider Optional provider (for example for PKCS11)
	 * @return The CSR
	 * @throws CryptoException If there was a problem generating the CSR
	 */
	public static PKCS10CertificationRequest generateCsr(X500Principal subjectDN, PublicKey publicKey,
			PrivateKey privateKey, SignatureType signatureType, String challenge, String unstructuredName,
			Extensions extensions, Provider provider) throws CryptoException {

		try {
			JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subjectDN,
					publicKey);

			// add challenge attribute
			if (challenge != null) {
				// PKCS#9 2.0: SHOULD use UTF8String encoding
				csrBuilder.addAttribute(pkcs_9_at_challengePassword, new DERUTF8String(challenge));
			}

			if (unstructuredName != null) {
				csrBuilder.addAttribute(pkcs_9_at_unstructuredName, new DERUTF8String(unstructuredName));
			}

			if (extensions != null) {
				csrBuilder.addAttribute(pkcs_9_at_extensionRequest, extensions.toASN1Primitive());
			}

			// fall back to bouncy castle provider if given provider does not support the requested algorithm
			if (provider != null && provider.getService("Signature", signatureType.jce()) == null) {
				provider = new BouncyCastleProvider();
			}

			ContentSigner contentSigner = null;

			if (provider == null) {
				contentSigner = new JcaContentSignerBuilder(signatureType.jce()).build(privateKey);
			} else {
				contentSigner = new JcaContentSignerBuilder(signatureType.jce()).setProvider(provider).build(privateKey);
			}

			PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);

			if (!verifyCsr(csr)) {
				throw new CryptoException(res.getString("NoVerifyGenPkcs10Csr.exception.message"));
			}

			return csr;
		} catch (OperatorCreationException e) {
			throw new CryptoException(res.getString("NoGeneratePkcs10Csr.exception.message"), e);
		}
	}


	/**
	 * Verify a PKCS #10 certificate signing request (CSR).
	 *
	 * @param csr The certificate signing request
	 * @return True if successfully verified
	 * @throws CryptoException
	 * 				If there was a problem verifying the CSR
	 */
	public static boolean verifyCsr(PKCS10CertificationRequest csr) throws CryptoException {
		try {
			PublicKey pubKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();

			ContentVerifierProvider contentVerifierProvider =
					new JcaContentVerifierProviderBuilder().setProvider("BC").build(pubKey);
			return csr.isSignatureValid(contentVerifierProvider);
		} catch (InvalidKeyException | OperatorCreationException | NoSuchAlgorithmException | PKCSException e) {
			throw new CryptoException(res.getString("NoVerifyPkcs10Csr.exception.message"), e);
		}
	}

	/**
	 * DER encode a CSR and PEM the encoding.
	 *
	 * @return The encoding
	 * @param csr
	 *            The CSR
	 * @throws CryptoException
	 * 				If CSR cannot be encoded
	 */
	public static byte[] getCsrEncodedDer(PKCS10CertificationRequest csr) throws CryptoException {
		try {
			return csr.getEncoded();
		} catch (IOException e) {
			throw new CryptoException(res.getString("NoEncodePkcs10Csr.exception.message"), e);
		}
	}

	/**
	 * DER encode a CSR and PEM the encoding.
	 *
	 * @return The PEM'd encoding
	 * @param csr
	 *            The CSR
	 * @throws CryptoException
	 *             If a problem occurs getting the PEM encoded CSR
	 */
	public static String getCsrEncodedDerPem(PKCS10CertificationRequest csr) throws CryptoException {
		try {
			// Base 64 encoding of CSR
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ASN1OutputStream deros = ASN1OutputStream.create(baos, ASN1Encoding.DER);
			deros.writeObject(csr.toASN1Structure().toASN1Primitive());
			String tmp = new String(Base64.encode(baos.toByteArray()));

			// Header
			String csrStr = BEGIN_CSR_FORM_1 + "\n";

			// Limit line lengths between header and footer
			for (int i = 0; i < tmp.length(); i += MAX_PRINTABLE_ENC_LINE_LENGTH) {
				int lineLength;

				if ((i + MAX_PRINTABLE_ENC_LINE_LENGTH) > tmp.length()) {
					lineLength = (tmp.length() - i);
				} else {
					lineLength = MAX_PRINTABLE_ENC_LINE_LENGTH;
				}

				csrStr += tmp.substring(i, (i + lineLength)) + "\n";
			}

			// Footer
			csrStr += END_CSR_FORM_1 + "\n";

			return csrStr;
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoPemPkcs10Csr.exception.message"), ex);
		}
	}

	/**
	 * Load a PKCS #10 CSR from the specified stream. The encoding of the CSR
	 * may be PEM or DER.
	 *
	 * @param data Byte array to load CSR from
	 * @return The CSR
	 * @throws IOException
	 *             An I/O error occurred
	 */
	public static PKCS10CertificationRequest loadCsr(byte[] data) throws IOException {

		byte[] csrBytes = null;
		// Assume file is PEM until we find out otherwise
		try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
				InputStreamReader inputStreamReader = new InputStreamReader(bais);
				LineNumberReader lnr = new LineNumberReader(inputStreamReader)) {

			String line = lnr.readLine();
			StringBuilder sbPem = new StringBuilder();

			if ((line != null) && (line.equals(BEGIN_CSR_FORM_1) || line.equals(BEGIN_CSR_FORM_2))) {
				while ((line = lnr.readLine()) != null) {
					if (line.equals(END_CSR_FORM_1) || line.equals(END_CSR_FORM_2)) {
						csrBytes = Base64.decode(sbPem.toString());
						break;
					}

					sbPem.append(line);
				}
			}
		}

		// Not PEM - must be DER encoded
		if (csrBytes == null) {
			csrBytes = data;
		}

		return new PKCS10CertificationRequest(csrBytes);
	}

	/**
	 * Extract sequence with extensions from CSR
	 *
	 * @param pkcs10Csr The CSR
	 * @return Extensions from that CSR (if any)
	 */
	public static X509ExtensionSet getExtensions(PKCS10CertificationRequest pkcs10Csr) {
		Attribute[] attributes = pkcs10Csr.getAttributes(pkcs_9_at_extensionRequest);
		X509ExtensionSet x509ExtensionSet = new X509ExtensionSet();
		if ((attributes != null) && (attributes.length > 0)) {
			ASN1Encodable[] attributeValues = attributes[0].getAttributeValues();
			if (attributeValues.length > 0) {
				ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(attributeValues[0]);
				x509ExtensionSet = new X509ExtensionSet(asn1Sequence);
			}
		}
		return x509ExtensionSet;
	}

}
