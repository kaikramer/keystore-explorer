/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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
 *
 */

package org.kse.crypto.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.kse.crypto.signing.SignatureType.RIPEMD160_RSA;
import static org.kse.crypto.signing.SignatureType.SHA1WITHRSAANDMGF1;
import static org.kse.crypto.signing.SignatureType.SHA1_DSA;
import static org.kse.crypto.signing.SignatureType.SHA1_ECDSA;
import static org.kse.crypto.signing.SignatureType.SHA1_RSA;
import static org.kse.crypto.signing.SignatureType.SHA224WITHRSAANDMGF1;
import static org.kse.crypto.signing.SignatureType.SHA224_DSA;
import static org.kse.crypto.signing.SignatureType.SHA224_RSA;
import static org.kse.crypto.signing.SignatureType.SHA256WITHRSAANDMGF1;
import static org.kse.crypto.signing.SignatureType.SHA256_DSA;
import static org.kse.crypto.signing.SignatureType.SHA256_ECDSA;
import static org.kse.crypto.signing.SignatureType.SHA256_RSA;
import static org.kse.crypto.signing.SignatureType.SHA384WITHRSAANDMGF1;
import static org.kse.crypto.signing.SignatureType.SHA384_DSA;
import static org.kse.crypto.signing.SignatureType.SHA384_ECDSA;
import static org.kse.crypto.signing.SignatureType.SHA384_RSA;
import static org.kse.crypto.signing.SignatureType.SHA512WITHRSAANDMGF1;
import static org.kse.crypto.signing.SignatureType.SHA512_DSA;
import static org.kse.crypto.signing.SignatureType.SHA512_ECDSA;
import static org.kse.crypto.signing.SignatureType.SHA512_RSA;
import static org.kse.crypto.signing.SignatureType.dsaSignatureTypes;
import static org.kse.crypto.signing.SignatureType.ecdsaSignatureTypes;
import static org.kse.crypto.signing.SignatureType.rsaSignatureTypes;

import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class SignatureTypeTest {

    @ParameterizedTest
    @MethodSource
    void signatureTypes(List<SignatureType> signatureTypes, List<SignatureType> expectedSignatureTypes) {
        assertThat(signatureTypes).isEqualTo(expectedSignatureTypes);
    }

    // @formatter:off
    private static Stream<Arguments> signatureTypes() {
        return Stream.of(
                Arguments.of(
                        rsaSignatureTypes(),
                        List.of(
                                RIPEMD160_RSA,
                                SHA1_RSA,
                                SHA224_RSA,
                                SHA256_RSA,
                                SHA384_RSA,
                                SHA512_RSA,
                                SHA1WITHRSAANDMGF1,
                                SHA224WITHRSAANDMGF1,
                                SHA256WITHRSAANDMGF1,
                                SHA384WITHRSAANDMGF1,
                                SHA512WITHRSAANDMGF1
                        )
                ),
                Arguments.of(
                        dsaSignatureTypes(),
                        List.of(
                                SHA1_DSA,
                                SHA224_DSA,
                                SHA256_DSA,
                                SHA384_DSA,
                                SHA512_DSA
                        )
                ),
                Arguments.of(
                        ecdsaSignatureTypes(),
                        List.of(
                                SHA1_ECDSA,
                                SHA256_ECDSA,
                                SHA384_ECDSA,
                                SHA512_ECDSA
                        )
                )
        );
    }
    // @formatter:on
}
