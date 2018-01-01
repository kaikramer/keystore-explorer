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

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.Date;
import java.util.ResourceBundle;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.kse.crypto.CryptoException;
import org.kse.crypto.signing.SignatureType;

/**
 * X.509 certificate generator.
 *
 */
public class X509CertificateGenerator {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
	private X509CertificateVersion version;

	/**
	 * Construct the generator.
	 *
	 * @param version
	 *            Version of generated certificates
	 */
	public X509CertificateGenerator(X509CertificateVersion version) {
		this.version = version;
	}

	/**
	 * Generate a certificate.
	 *
	 * @param subject
	 *            Certificate subject
	 * @param issuer
	 *            Certificate issuer
	 * @param validityStart
	 *            Validity start date of certificate in msecs
	 * @param validityEnd
	 *            Validity end date of certificate in msecs
	 * @param publicKey
	 *            Public part of key pair
	 * @param privateKey
	 *            Private part of key pair
	 * @param signatureType
	 *            Signature Type
	 * @param serialNumber
	 *            Serial number
	 * @return The generated certificate
	 * @throws CryptoException
	 *             If there was a problem generating the certificate
	 */
	public X509Certificate generate(X500Name subject, X500Name issuer, Date validityStart, Date validityEnd, PublicKey publicKey,
			PrivateKey privateKey, SignatureType signatureType, BigInteger serialNumber) throws CryptoException {
		return generate(subject, issuer, validityStart, validityEnd, publicKey, privateKey, signatureType, serialNumber, null,
				new BouncyCastleProvider());
	}

	/**
	 * Generate a certificate.
	 *
	 * @param subject
	 *            Certificate subject
	 * @param issuer
	 *            Certificate issuer
	 * @param validityStart
	 *            Validity start date of certificate in msecs
	 * @param validityEnd
	 *            Validity end date of certificate in msecs
	 * @param publicKey
	 *            Public part of key pair
	 * @param privateKey
	 *            Private part of key pair
	 * @param signatureType
	 *            Signature Type
	 * @param serialNumber
	 *            Serial number
	 * @param extensions
	 *            Extensions, ignored by version 1 generators
	 * @return The generated certificate
	 * @throws CryptoException
	 *             If there was a problem generating the certificate
	 */
	public X509Certificate generate(X500Name subject, X500Name issuer, Date validityStart, Date validityEnd, PublicKey publicKey,
			PrivateKey privateKey, SignatureType signatureType, BigInteger serialNumber, X509Extension extensions,
			Provider provider)
					throws CryptoException {
		if (version == X509CertificateVersion.VERSION1) {
			// TODO
			return generateVersion1(subject, issuer, validityStart, validityEnd, publicKey, privateKey, signatureType, serialNumber);
		} else {
			try {
				return generateVersion3(subject, issuer, validityStart, validityEnd, publicKey, privateKey, signatureType, serialNumber,
						extensions, provider);
			} catch (CertIOException e) {
				throw new CryptoException(e);
			}
		}
	}

	/**
	 * Generate a self-signed certificate.
	 *
	 * @param name
	 *            Certificate subject and issuer
	 * @param validity
	 *            Validity period of certificate in msecs
	 * @param publicKey
	 *            Public part of key pair
	 * @param privateKey
	 *            Private part of key pair
	 * @param signatureType
	 *            Signature Type
	 * @param serialNumber
	 *            Serial number
	 * @return The generated certificate
	 * @throws CryptoException
	 *             If there was a problem generating the certificate
	 */
	public X509Certificate generateSelfSigned(X500Name name, long validity, PublicKey publicKey, PrivateKey privateKey,
			SignatureType signatureType, BigInteger serialNumber) throws CryptoException {
		Date validityStart = new Date();
		Date validityEnd = new Date(validityStart.getTime() + validity);
		return generateSelfSigned(name, validityStart, validityEnd, publicKey, privateKey, signatureType, serialNumber);
	}

	/**
	 * Generate a self-signed certificate.
	 *
	 * @param name
	 *            Certificate subject and issuer
	 * @param validityStart
	 *            Validity start date of certificate in msecs
	 * @param validityEnd
	 *            Validity end date of certificate in msecs
	 * @param publicKey
	 *            Public part of key pair
	 * @param privateKey
	 *            Private part of key pair
	 * @param signatureType
	 *            Signature Type
	 * @param serialNumber
	 *            Serial number
	 * @return The generated certificate
	 * @throws CryptoException
	 *             If there was a problem generating the certificate
	 */
	public X509Certificate generateSelfSigned(X500Name name, Date validityStart, Date validityEnd, PublicKey publicKey, PrivateKey privateKey,
			SignatureType signatureType, BigInteger serialNumber) throws CryptoException {
		return generateSelfSigned(name, validityStart, validityEnd, publicKey, privateKey, signatureType, serialNumber, null,
				new BouncyCastleProvider());
	}

	/**
	 * Generate a self-signed certificate.
	 *
	 * @param name
	 *            Certificate subject and issuer
	 * @param validityStart
	 *            Validity start date of certificate in msecs
	 * @param validityEnd
	 *            Validity end date of certificate in msecs
	 * @param publicKey
	 *            Public part of key pair
	 * @param privateKey
	 *            Private part of key pair
	 * @param signatureType
	 *            Signature Type
	 * @param serialNumber
	 *            Serial number
	 * @param extensions
	 *            Extensions, ignored by version 1 generators
	 * @return The generated certificate
	 * @throws CryptoException
	 *             If there was a problem generating the certificate
	 */
	public X509Certificate generateSelfSigned(X500Name name, Date validityStart, Date validityEnd, PublicKey publicKey, PrivateKey privateKey,
			SignatureType signatureType, BigInteger serialNumber, X509Extension extensions, Provider provider)
					throws CryptoException {
		return generate(name, name, validityStart, validityEnd, publicKey, privateKey, signatureType, serialNumber, extensions, provider);
	}

	private X509Certificate generateVersion1(X500Name subject, X500Name issuer, Date validityStart, Date validityEnd, PublicKey publicKey,
			PrivateKey privateKey, SignatureType signatureType, BigInteger serialNumber) throws CryptoException {
		Date notBefore = validityStart == null ? new Date() : validityStart;
		Date notAfter = validityEnd == null ? new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365)) : validityEnd;

		JcaX509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(issuer, serialNumber, notBefore,
				notAfter, subject, publicKey);

		try {
			ContentSigner certSigner = new JcaContentSignerBuilder(signatureType.jce()).setProvider("BC").build(
					privateKey);
			return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(certSigner));
		} catch (CertificateException | IllegalStateException | OperatorCreationException ex) {
			throw new CryptoException(res.getString("CertificateGenFailed.exception.message"), ex);
		}
	}

	private X509Certificate generateVersion3(X500Name subject, X500Name issuer, Date validityStart, Date validityEnd, PublicKey publicKey,
			PrivateKey privateKey, SignatureType signatureType, BigInteger serialNumber, X509Extension extensions,
			Provider provider)
					throws CryptoException, CertIOException {
		Date notBefore = validityStart == null ? new Date() : validityStart;
		Date notAfter = validityEnd == null ? new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365)) : validityEnd;

		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore,
				notAfter, subject, publicKey);

		if (extensions != null) {
			for (String oid : extensions.getCriticalExtensionOIDs()) {
				certBuilder.addExtension(new ASN1ObjectIdentifier(oid), true, getExtensionValue(extensions, oid));
			}

			for (String oid : extensions.getNonCriticalExtensionOIDs()) {
				certBuilder.addExtension(new ASN1ObjectIdentifier(oid), false, getExtensionValue(extensions, oid));
			}
		}

		try {
			ContentSigner certSigner = null;

			if (provider == null) {
				certSigner = new JcaContentSignerBuilder(signatureType.jce()).setProvider("BC").build(privateKey);
			} else {
				certSigner = new JcaContentSignerBuilder(signatureType.jce()).setProvider(provider).build(privateKey);
			}

			return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(certSigner));
		} catch (CertificateException | IllegalStateException | OperatorCreationException ex) {
			throw new CryptoException(res.getString("CertificateGenFailed.exception.message"), ex);
		}
	}

	private ASN1Encodable getExtensionValue(X509Extension extensions, String oid) throws CryptoException {
		try (ASN1InputStream ais = new ASN1InputStream(extensions.getExtensionValue(oid))) {
			return ais.readObject();
		} catch (IOException ex) {
			throw new CryptoException(res.getString("CertificateGenFailed.exception.message"), ex);
		}
	}
}
