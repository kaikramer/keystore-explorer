/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import net.sf.keystore_explorer.crypto.TestCaseCrypto;
import net.sf.keystore_explorer.crypto.csr.CsrType;
import net.sf.keystore_explorer.crypto.csr.pkcs10.Pkcs10Util;
import net.sf.keystore_explorer.crypto.csr.spkac.Spkac;
import net.sf.keystore_explorer.crypto.csr.spkac.SpkacSubject;
import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.crypto.keypair.KeyPairUtil;
import net.sf.keystore_explorer.crypto.x509.X509CertificateGenerator;
import net.sf.keystore_explorer.crypto.x509.X509CertificateVersion;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;

import static net.sf.keystore_explorer.crypto.csr.CsrType.PKCS10;
import static net.sf.keystore_explorer.crypto.csr.CsrType.SPKAC;
import static net.sf.keystore_explorer.crypto.keypair.KeyPairType.DSA;
import static net.sf.keystore_explorer.crypto.keypair.KeyPairType.RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.MD2_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.MD5_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.RIPEMD128_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.RIPEMD160_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.RIPEMD256_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA1_DSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA1_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA224_DSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA224_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA256_DSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA256_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA384_DSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA384_RSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA512_DSA;
import static net.sf.keystore_explorer.crypto.signing.SignatureType.SHA512_RSA;
import static net.sf.keystore_explorer.crypto.x509.X509CertificateVersion.VERSION1;
import static net.sf.keystore_explorer.crypto.x509.X509CertificateVersion.VERSION3;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for all signature algorithms for certificate and CSR generation.
 *
 */
public class TestSignatureAlgorithms extends TestCaseCrypto {
	private KeyPair rsaKeyPair;
	private KeyPair dsaKeyPair;
	private X509CertificateGenerator generatorv1;
	private X509CertificateGenerator generatorv3;

	@Before
	public void setUp() throws Exception {
		rsaKeyPair = KeyPairUtil.generateKeyPair(RSA, 1024, new BouncyCastleProvider());
		dsaKeyPair = KeyPairUtil.generateKeyPair(DSA, 512, new BouncyCastleProvider());
		generatorv1 = new X509CertificateGenerator(VERSION1);
		generatorv3 = new X509CertificateGenerator(VERSION3);
	}

	@Test
	public void rsaMd2Spkac() throws Exception {
		doTest(RSA, MD2_RSA, SPKAC);
	}

	@Test
	public void rsaMd5Spkac() throws Exception {
		doTest(RSA, MD5_RSA, SPKAC);
	}

	@Test
	public void rsaSha1Spkac() throws Exception {
		doTest(RSA, SHA1_RSA, SPKAC);
	}

	@Test
	public void rsaSha224Spkac() throws Exception {
		doTest(RSA, SHA224_RSA, SPKAC);
	}

	@Test
	public void rsaSha256Spkac() throws Exception {
		doTest(RSA, SHA256_RSA, SPKAC);
	}

	@Test
	public void rsaSha384Spkac() throws Exception {
		doTest(RSA, SHA384_RSA, SPKAC);
	}

	@Test
	public void rsaSha512Spkac() throws Exception {
		doTest(RSA, SHA512_RSA, SPKAC);
	}

	@Test
	public void rsaRipemd128Spkac() throws Exception {
		doTest(RSA, RIPEMD128_RSA, SPKAC);
	}

	@Test
	public void rsaRipemd160Spkac() throws Exception {
		doTest(RSA, RIPEMD160_RSA, SPKAC);
	}

	@Test
	public void rsaRipemd256Spkac() throws Exception {
		doTest(RSA, RIPEMD256_RSA, SPKAC);
	}

	@Test
	public void dsaSha1Spkac() throws Exception {
		doTest(DSA, SHA1_DSA, SPKAC);
	}

	@Test
	public void dsaSha224Spkac() throws Exception {
		doTest(DSA, SHA224_DSA, SPKAC);
	}

	@Test
	public void dsaSha256Spkac() throws Exception {
		doTest(DSA, SHA256_DSA, SPKAC);
	}

	@Test
	public void dsaSha384Spkac() throws Exception {
		doTest(DSA, SHA384_DSA, SPKAC);
	}

	@Test
	public void dsaSha512Spkac() throws Exception {
		doTest(DSA, SHA512_DSA, SPKAC);
	}

	@Test
	public void rsaMd2Pkcs10() throws Exception {
		doTest(RSA, MD2_RSA, PKCS10);
	}

	@Test
	public void rsaMd5Pkcs10() throws Exception {
		doTest(RSA, MD5_RSA, PKCS10);
	}

	@Test
	public void rsaSha1Pkcs10() throws Exception {
		doTest(RSA, SHA1_RSA, PKCS10);
	}

	@Test
	public void rsaSha224Pkcs10() throws Exception {
		doTest(RSA, SHA224_RSA, PKCS10);
	}

	@Test
	public void rsaSha256Pkcs10() throws Exception {
		doTest(RSA, SHA256_RSA, PKCS10);
	}

	@Test
	public void rsaSha384Pkcs10() throws Exception {
		doTest(RSA, SHA384_RSA, PKCS10);
	}

	@Test
	public void rsaSha512Pkcs10() throws Exception {
		doTest(RSA, SHA512_RSA, PKCS10);
	}

	@Test
	public void rsaRipemd128Pkcs10() throws Exception {
		doTest(RSA, RIPEMD128_RSA, PKCS10);
	}

	@Test
	public void rsaRipemd160Pkcs10() throws Exception {
		doTest(RSA, RIPEMD160_RSA, PKCS10);
	}

	@Test
	public void rsaRipemd256Pkcs10() throws Exception {
		doTest(RSA, RIPEMD256_RSA, PKCS10);
	}

	@Test
	public void dsaSha1Pkcs10() throws Exception {
		doTest(DSA, SHA1_DSA, PKCS10);
	}

	@Test
	public void dsaSha224Pkcs10() throws Exception {
		doTest(DSA, SHA224_DSA, PKCS10);
	}

	@Test
	public void dsaSha256Pkcs10() throws Exception {
		doTest(DSA, SHA256_DSA, PKCS10);
	}

	@Test
	public void dsaSha384Pkcs10() throws Exception {
		doTest(DSA, SignatureType.SHA384_DSA, PKCS10);
	}

	@Test
	public void dsaSha512Pkcs10() throws Exception {
		doTest(DSA, SignatureType.SHA512_DSA, PKCS10);
	}

	private void doTest(KeyPairType keyPairType, SignatureType signatureType, CsrType csrType) throws Exception {
		doTest2(keyPairType, signatureType, csrType, X509CertificateVersion.VERSION1);
		doTest2(keyPairType, signatureType, csrType, X509CertificateVersion.VERSION3);
	}

	private void doTest2(KeyPairType keyPairType, SignatureType signatureType, CsrType csrType,
			X509CertificateVersion version) throws Exception {
		KeyPair keyPair = null;

		if (keyPairType == KeyPairType.RSA) {
			keyPair = rsaKeyPair;
		} else {
			keyPair = dsaKeyPair;
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
			assertTrue(spkac.verify());
		} else {
			PKCS10CertificationRequest pkcs10 = Pkcs10Util.generateCsr(cert, privateKey, signatureType, "w/e", "w/e",
					false, new BouncyCastleProvider());
			byte[] encoded = Pkcs10Util.getCsrEncodedDer(pkcs10);
			pkcs10 = Pkcs10Util.loadCsr(new ByteArrayInputStream(encoded));
			assertTrue(Pkcs10Util.verifyCsr(pkcs10));
		}
	}
}
