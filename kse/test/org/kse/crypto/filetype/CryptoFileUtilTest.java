package org.kse.crypto.filetype;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.IOException;
import java.security.Security;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class CryptoFileUtilTest {

	private static final String TEST_FILES_PATH = "test/testdata/CryptoFileUtilTest";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@ParameterizedTest
	@CsvSource({
			// formats for X.509 certificates
			"cert.pem.cer, CERT",
			"cert.multi.pem.cer, CERT",
			"filetype_detection_issue.cer, CERT",
			"cert.der.cer, CERT",
			"cert.pkipath, CERT",
			"cert.spc, CERT",
			"cert.p7, CERT",
			"cert.p7b, CERT",

			// certificate signing request formats
			"csr.p10, PKCS10_CSR",
			"csr.spkac, SPKAC_CSR",

			// keystore formats
			"keystore.bcfks, BCFKS_KS",
			"keystore.bks, BKS_KS",
			"keystore.jceks, JCEKS_KS",
			"keystore.jks, JKS_KS",
			"keystore.p12, PKCS12_KS",
			"keystore.uber, UBER_KS",

			// EC private key formats
			"ec.enc.pem.pkcs8, ENC_PKCS8_PVK",
			"ec.enc.der.pkcs8, ENC_PKCS8_PVK",
			"ec.unenc.pem.pkcs8, UNENC_PKCS8_PVK",
			"ec.unenc.der.pkcs8, UNENC_PKCS8_PVK",
			"ec.enc.pem.key, ENC_OPENSSL_PVK",
			"ec.unenc.pem.key, UNENC_OPENSSL_PVK",
			"ec.unenc.der.key, UNENC_OPENSSL_PVK",

			// EC public key formats
			"ec.pem.pub, OPENSSL_PUB",
			"ec.der.pub, OPENSSL_PUB",

			// RSA private key formats
			"rsa.enc.pem.pkcs8, ENC_PKCS8_PVK",
			"rsa.enc.der.pkcs8, ENC_PKCS8_PVK",
			"rsa.unenc.pem.pkcs8, UNENC_PKCS8_PVK",
			"rsa.unenc.der.pkcs8, UNENC_PKCS8_PVK",
			"rsa.enc.pem.key, ENC_OPENSSL_PVK",
			"rsa.unenc.der.key, UNENC_OPENSSL_PVK",
			"rsa.unenc.pem.key, UNENC_OPENSSL_PVK",
			"rsa.enc.pvk, ENC_MS_PVK",
			"rsa.unenc.pvk, UNENC_MS_PVK",

			// RSA public key formats
			"rsa.pem.pub, OPENSSL_PUB",
			"rsa.der.pub, OPENSSL_PUB",

			// CRLs
			"test.pem.crl, CRL",
			"test.der.crl, CRL",

			// text file without any cryptographic content
			"unknown.txt, UNKNOWN",

			// an empty file might cause some trouble
			"empty.txt, UNKNOWN",

			// TODO A binary file like an extension template might look similar to some other file types...
			// In this case the file has the same characteristics as a UBER v0 keystore.
			// "CA.template, UNKNOWN",
	})
	void detectFileType(String fileName, CryptoFileType expectedResult) throws IOException {
		byte[] data = FileUtils.readFileToByteArray(new File(TEST_FILES_PATH, fileName));

		assertEquals(expectedResult, CryptoFileUtil.detectFileType(data));
	}
}