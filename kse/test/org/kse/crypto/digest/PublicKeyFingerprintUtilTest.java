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

package org.kse.crypto.digest;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.kse.crypto.CryptoException;
import org.kse.crypto.x509.X509CertUtil;

class PublicKeyFingerprintUtilTest {

    private static final String TEST_FILES_PATH = "test/testdata/PublicKeyFingerprintUtilTest";

    @ParameterizedTest(name = "[{index}] {0} - Algorithm: {1}")
    @CsvSource({
            "RSA_4096_GTS_Root_R1.cer,      SKI_METHOD1,        e4af2b26711a2b4827852f52662ceff08913713e",
            "RSA_4096_GTS_Root_R1.cer,      SKI_METHOD2,        462ceff08913713e",
            "RSA_4096_GTS_Root_R1.cer,      SHA1_OVER_SPKI,     85565349beea4ab18649b56171a995cf48883660",
            "RSA_4096_GTS_Root_R1.cer,      SHA256_OVER_SPKI,   871a9194f4eed5b312ff40c84c1d524aed2f778bbff25f138cf81f680a7adc67",
            "EC_P256_www.google.com.cer,    SKI_METHOD1,        79baea0fd659fcd37acc960a2161523b6f5325cd",
            "EC_P256_www.google.com.cer,    SKI_METHOD2,        4161523b6f5325cd",
            "EC_P256_www.google.com.cer,    SHA1_OVER_SPKI,     4c017a8b1035ba92b6e6fe4b0fbb1accfe99cd29",
            "EC_P256_www.google.com.cer,    SHA256_OVER_SPKI,   3e02296699487746d63543f1429d583a237367388cb31d7ad8059a26ba0c214f",
            "EC_P384_DigiCertRootG5.cer,    SKI_METHOD1,        f08c9871393865c23a1ba617661dc8ed65de9236",
            "EC_P384_DigiCertRootG5.cer,    SKI_METHOD2,        461dc8ed65de9236",
            "EC_P384_DigiCertRootG5.cer,    SHA1_OVER_SPKI,     84e2765856529494e5bd76b68ddae50af1b4f0e0",
            "EC_P384_DigiCertRootG5.cer,    SHA256_OVER_SPKI,   8a6e2e9bcec665a03c24d24a1efe631881a8c4a54c96fe00160fa7b0cc535fcd",
            "Ed25519_CA.cer,                SKI_METHOD1,        c4490b6476315669a96e2d8a9a6a10b9b8ade5f6",
            "Ed25519_CA.cer,                SKI_METHOD2,        4a6a10b9b8ade5f6",
            "Ed25519_CA.cer,                SHA1_OVER_SPKI,     eb732d6557c67b34ece125dae80e21e1d51bf5a6",
            "Ed25519_CA.cer,                SHA256_OVER_SPKI,   38b5d52d0ea1f209be866bcaaa89b516bd0c20c04d4e30d0811c880b8226ae80"
    })
    void calculateFingerprint(String certFile, PublicKeyFingerprintAlgorithm fpAlgorithm, String expectedValueHex)
            throws IOException, CryptoException {

        byte[] data = FileUtils.readFileToByteArray(new File(TEST_FILES_PATH, certFile));
        PublicKey publicKey = X509CertUtil.loadCertificates(data)[0].getPublicKey();

        byte[] calculatedFingerprint = PublicKeyFingerprintUtil.calculateFingerprint(publicKey, fpAlgorithm);

        assertThat(Hex.toHexString(calculatedFingerprint).toUpperCase()).isEqualToIgnoringCase(expectedValueHex);
    }

}