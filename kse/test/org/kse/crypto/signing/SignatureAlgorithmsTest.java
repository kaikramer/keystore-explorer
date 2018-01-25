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

import static org.assertj.core.api.Assertions.assertThat;
import static org.kse.crypto.keypair.KeyPairType.DSA;
import static org.kse.crypto.keypair.KeyPairType.RSA;
import static org.kse.crypto.x509.X509CertificateVersion.VERSION1;
import static org.kse.crypto.x509.X509CertificateVersion.VERSION3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.csr.CsrType;
import org.kse.crypto.csr.pkcs10.Pkcs10Util;
import org.kse.crypto.csr.spkac.Spkac;
import org.kse.crypto.csr.spkac.SpkacSubject;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.x509.X509CertificateGenerator;
import org.kse.crypto.x509.X509CertificateVersion;

/**
 * Unit tests for all signature algorithms for certificate and CSR generation.
 *
 */
public class SignatureAlgorithmsTest extends CryptoTestsBase {
	private static KeyPair rsaKeyPair;
	private static KeyPair dsaKeyPair;
	private static KeyPair ecKeyPair;
	private static X509CertificateGenerator generatorv1;
	private static X509CertificateGenerator generatorv3;

	@BeforeAll
	private static void setUp() throws Exception {
		rsaKeyPair = KeyPairUtil.generateKeyPair(RSA, 2048, BC);
		dsaKeyPair = KeyPairUtil.generateKeyPair(DSA, 1024, BC);
		ecKeyPair = KeyPairUtil.generateECKeyPair("prime192v1", BC);
		generatorv1 = new X509CertificateGenerator(VERSION1);
		generatorv3 = new X509CertificateGenerator(VERSION3);
	}

	@ParameterizedTest
	@CsvSource({
		"RSA, MD2_RSA, SPKAC",
		"RSA, MD5_RSA, SPKAC",
		"RSA, SHA1_RSA, SPKAC",
		"RSA, SHA224_RSA, SPKAC",
		"RSA, SHA256_RSA, SPKAC",
		"RSA, SHA384_RSA, SPKAC",
		"RSA, SHA512_RSA, SPKAC",
		"RSA, RIPEMD128_RSA, SPKAC",
		"RSA, RIPEMD160_RSA, SPKAC",
		"RSA, RIPEMD256_RSA, SPKAC",
		"DSA, SHA1_DSA, SPKAC",
		"DSA, SHA224_DSA, SPKAC",
		"DSA, SHA256_DSA, SPKAC",
		"DSA, SHA384_DSA, SPKAC",
		"DSA, SHA512_DSA, SPKAC",
		"RSA, MD2_RSA, PKCS10",
		"RSA, MD5_RSA, PKCS10",
		"RSA, SHA1_RSA, PKCS10",
		"RSA, SHA224_RSA, PKCS10",
		"RSA, SHA256_RSA, PKCS10",
		"RSA, SHA384_RSA, PKCS10",
		"RSA, SHA512_RSA, PKCS10",
		"RSA, RIPEMD128_RSA, PKCS10",
		"RSA, RIPEMD160_RSA, PKCS10",
		"RSA, RIPEMD256_RSA, PKCS10",
		"DSA, SHA1_DSA, PKCS10",
		"DSA, SHA224_DSA, PKCS10",
		"DSA, SHA256_DSA, PKCS10",
		"DSA, SHA384_DSA, PKCS10",
		"DSA, SHA512_DSA, PKCS10",
		"EC, SHA1_ECDSA, PKCS10",
		"EC, SHA224_ECDSA, PKCS10",
		"EC, SHA256_ECDSA, PKCS10",
		"EC, SHA384_ECDSA, PKCS10",
		"EC, SHA512_ECDSA, PKCS10",
		// combination EC/SPKAC not supported right now and probably never will be
	})
	public void testSignCertificateAndCSR(KeyPairType keyPairType, SignatureType signatureType, CsrType csrType)
			throws Exception {
		doTest(keyPairType, signatureType, csrType, X509CertificateVersion.VERSION1);
		doTest(keyPairType, signatureType, csrType, X509CertificateVersion.VERSION3);
	}

	private void doTest(KeyPairType keyPairType, SignatureType signatureType, CsrType csrType,
			X509CertificateVersion version) throws Exception {
		KeyPair keyPair = null;

		switch (keyPairType) {
		case RSA:
			keyPair = rsaKeyPair;
			break;
		case DSA:
			keyPair = dsaKeyPair;
			break;
		case EC:
			keyPair = ecKeyPair;
			break;
		default:
			throw new InvalidParameterException();
		}

		X500Name name = new X500Name("cn=this");

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		X509Certificate cert = null;

		if (version == X509CertificateVersion.VERSION1) {
			cert = generatorv1.generateSelfSigned(name, 1000, publicKey, privateKey, signatureType, BigInteger.ONE);
		} else {
			cert = generatorv3.generateSelfSigned(name, 1000, publicKey, privateKey, signatureType, BigInteger.ONE);
		}

		if (csrType == CsrType.SPKAC) {
			Spkac spkac = new Spkac("whatever", signatureType, new SpkacSubject(name), publicKey, privateKey);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			spkac.output(baos);
			spkac = new Spkac(new ByteArrayInputStream(baos.toByteArray()));
			assertThat(spkac.verify()).isTrue();
		} else {
			PKCS10CertificationRequest pkcs10 = Pkcs10Util.generateCsr(cert, privateKey, signatureType, "w/e", "w/e",
					false, new BouncyCastleProvider());
			byte[] encoded = Pkcs10Util.getCsrEncodedDer(pkcs10);
			pkcs10 = Pkcs10Util.loadCsr(new ByteArrayInputStream(encoded));
			assertThat(Pkcs10Util.verifyCsr(pkcs10)).isTrue();
		}
	}
}
