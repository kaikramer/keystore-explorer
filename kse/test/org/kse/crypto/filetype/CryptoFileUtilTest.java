/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

package org.kse.crypto.filetype;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.IOException;
import java.security.Security;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.kse.KSE;

class CryptoFileUtilTest {

    private static final String TEST_FILES_PATH = "test/testdata/CryptoFileUtilTest";

    static {
        Security.addProvider(KSE.BC);
    }

    @ParameterizedTest
    // @formatter:off
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

            // base64 encoded cert file, but no PEM header/footer
            "cert.base64.txt, CERT",

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
            "ec.unenc.der.b64.pkcs8, UNENC_PKCS8_PVK",
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

            // JWTs
            "test.jwt, JSON_WEB_TOKEN",

            // various PEM files with format issues like trailing whitespace, long lines, ...
            "problematic-pem1.crl, CRL",
            "problematic-pem2.crl, CRL",
            "problematic-pem3.crl, CRL",
            "problematic-pem4.p10, PKCS10_CSR",
            "problematic-pem5.cer, CERT",

            // text file without any cryptographic content
            "unknown.txt, UNKNOWN",

            // an empty file might cause some trouble
            "empty.txt, UNKNOWN",

            // TODO A binary file like an extension template might look similar to some other file types...
            // In this case the file has the same characteristics as a UBER v0 keystore.
            // "CA.template, UNKNOWN",
    })
    // @formatter:on
    void detectFileType(String fileName, CryptoFileType expectedResult) throws IOException {
        byte[] data = FileUtils.readFileToByteArray(new File(TEST_FILES_PATH, fileName));

        assertEquals(expectedResult, CryptoFileUtil.detectFileType(data));
    }
}