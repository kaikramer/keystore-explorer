/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.stream.Stream;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.kse.KSE;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Unit tests for {@link JwsSigner}.
 * <p>
 * Covers all non-HMAC JWS signature algorithms: RSA (RSASSA-PKCS1-v1_5 and
 * RSASSA-PSS), EC (ECDSA over P-256 / P-384 / P-521), and EdDSA (Ed25519).
 */
public class JwsSignerTest extends CryptoTestsBase {

    private static KeyPair rsaKeyPair;
    private static KeyPair ecP256KeyPair;
    private static KeyPair ecP384KeyPair;
    private static KeyPair ecP521KeyPair;
    private static KeyPair ed25519KeyPair;
    private static KeyPair ed448KeyPair;

    @BeforeAll
    static void setUpKeys() throws Exception {
        rsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 2048, KSE.BC);
        ecP256KeyPair = KeyPairUtil.generateECKeyPair("P-256", KSE.BC);
        ecP384KeyPair = KeyPairUtil.generateECKeyPair("P-384", KSE.BC);
        ecP521KeyPair = KeyPairUtil.generateECKeyPair("P-521", KSE.BC);
        ed25519KeyPair = KeyPairUtil.generateECKeyPair("Ed25519", KSE.BC);
        ed448KeyPair = KeyPairUtil.generateECKeyPair("Ed448", KSE.BC);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static JWTClaimsSet buildClaimsSet() {
        return new JWTClaimsSet.Builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .audience("test-audience")
                .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                .claim("custom", "value")
                .build();
    }

    private static KeyPair ecKeyPairFor(String curveName) {
        return switch (curveName) {
            case "P-256" -> ecP256KeyPair;
            case "P-384" -> ecP384KeyPair;
            case "P-521" -> ecP521KeyPair;
            default -> throw new IllegalArgumentException("Unknown curve: " + curveName);
        };
    }

    /**
     * Builds an {@link ECDSAVerifier} from a nimbus {@link ECKey} constructed
     * directly from the raw x/y coordinates of the public key, avoiding any
     * dependency on the JCA curve-spec implementation of the key.
     */
    private static ECDSAVerifier buildECDSAVerifier(Curve jwsCurve, ECPublicKey publicKey) throws Exception {
        ECKey ecKey = new ECKey.Builder(jwsCurve, publicKey).build();
        return new ECDSAVerifier(ecKey);
    }

    private static BcEd25519Verifier buildEd25519Verifier() throws Exception {
        Ed25519PrivateKeyParameters params =
                (Ed25519PrivateKeyParameters) PrivateKeyFactory.createKey(ed25519KeyPair.getPrivate().getEncoded());
        Base64URL encodedPub = Base64URL.encode(params.generatePublicKey().getEncoded());
        OctetKeyPair publicOkp = new OctetKeyPair.Builder(Curve.Ed25519, encodedPub).build();
        return new BcEd25519Verifier(publicOkp);
    }

    private static BcEd448Verifier buildEd448Verifier() throws Exception {
        Ed448PrivateKeyParameters params =
                (Ed448PrivateKeyParameters) PrivateKeyFactory.createKey(ed448KeyPair.getPrivate().getEncoded());
        Base64URL encodedPub = Base64URL.encode(params.generatePublicKey().getEncoded());
        OctetKeyPair publicOkp = new OctetKeyPair.Builder(Curve.Ed448, encodedPub).build();
        return new BcEd448Verifier(publicOkp);
    }

    /**
     * Verifies that the claims round-trip correctly through the signed JWT.
     */
    private static void assertClaimsPreserved(SignedJWT signedJWT, JWTClaimsSet expected) throws Exception {
        JWTClaimsSet actual = signedJWT.getJWTClaimsSet();
        assertThat(actual.getSubject()).isEqualTo(expected.getSubject());
        assertThat(actual.getIssuer()).isEqualTo(expected.getIssuer());
        assertThat(actual.getAudience()).containsExactlyInAnyOrderElementsOf(expected.getAudience());
        assertThat(actual.getStringClaim("custom")).isEqualTo("value");
    }

    /**
     * Serializes the JWT, parses it back from the compact serialization, and
     * verifies that the signature is still valid – proving end-to-end correctness.
     */
    private static void assertRoundTripVerification(SignedJWT signedJWT, JWSVerifier verifier) throws Exception {
        String compact = signedJWT.serialize();
        SignedJWT parsed = SignedJWT.parse(compact);
        assertThat(parsed.verify(verifier)).isTrue();
        // compact serialization must be exactly three dot-separated Base64URL parts
        assertThat(compact.split("\\.")).hasSize(3);
    }

    // -----------------------------------------------------------------------
    // RSA algorithms (RSASSA-PKCS1-v1_5 and RSASSA-PSS)
    // -----------------------------------------------------------------------

    static Stream<Arguments> rsaAlgorithms() {
        return Stream.of(
                Arguments.of(JWSAlgorithm.RS256),
                Arguments.of(JWSAlgorithm.RS384),
                Arguments.of(JWSAlgorithm.RS512),
                Arguments.of(JWSAlgorithm.PS256),
                Arguments.of(JWSAlgorithm.PS384),
                Arguments.of(JWSAlgorithm.PS512)
        );
    }

    @ParameterizedTest(name = "RSA sign+verify – {0} (no provider)")
    @MethodSource("rsaAlgorithms")
    void testSignJwtWithRsaAlgorithm(JWSAlgorithm algorithm) throws Exception {
        JWTClaimsSet claimsSet = buildClaimsSet();

        SignedJWT signedJWT = JwsSigner.signJwt(algorithm, null, claimsSet, rsaKeyPair.getPrivate(), null);

        assertThat(signedJWT).isNotNull();
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(algorithm);
        assertThat(signedJWT.getHeader().getKeyID()).isNull();

        RSASSAVerifier verifier = new RSASSAVerifier((RSAPublicKey) rsaKeyPair.getPublic());
        assertThat(signedJWT.verify(verifier)).isTrue();
        assertClaimsPreserved(signedJWT, claimsSet);
        assertRoundTripVerification(signedJWT, verifier);
    }

    @ParameterizedTest(name = "RSA sign+verify – {0} (with BC provider)")
    @MethodSource("rsaAlgorithms")
    void testSignJwtWithRsaAlgorithmAndBcProvider(JWSAlgorithm algorithm) throws Exception {
        JWTClaimsSet claimsSet = buildClaimsSet();

        SignedJWT signedJWT = JwsSigner.signJwt(algorithm, null, claimsSet, rsaKeyPair.getPrivate(), KSE.BC);

        assertThat(signedJWT).isNotNull();
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(algorithm);

        RSASSAVerifier verifier = new RSASSAVerifier((RSAPublicKey) rsaKeyPair.getPublic());
        assertThat(signedJWT.verify(verifier)).isTrue();
    }

    // -----------------------------------------------------------------------
    // EC algorithms (ECDSA over P-256, P-384, P-521)
    // -----------------------------------------------------------------------

    static Stream<Arguments> ecAlgorithmsAndCurves() {
        return Stream.of(
                Arguments.of(JWSAlgorithm.ES256, Curve.P_256, "P-256"),
                Arguments.of(JWSAlgorithm.ES384, Curve.P_384, "P-384"),
                Arguments.of(JWSAlgorithm.ES512, Curve.P_521, "P-521")
        );
    }

    @ParameterizedTest(name = "ECDSA sign+verify – {0} / {1} (no provider)")
    @MethodSource("ecAlgorithmsAndCurves")
    void testSignJwtWithEcAlgorithm(JWSAlgorithm algorithm, Curve curve, String curveName) throws Exception {
        KeyPair keyPair = ecKeyPairFor(curveName);
        JWTClaimsSet claimsSet = buildClaimsSet();

        SignedJWT signedJWT = JwsSigner.signJwt(algorithm, curve, claimsSet, keyPair.getPrivate(), null);

        assertThat(signedJWT).isNotNull();
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(algorithm);
        assertThat(signedJWT.getHeader().getKeyID()).isNull();

        ECDSAVerifier verifier = buildECDSAVerifier(curve, (ECPublicKey) keyPair.getPublic());
        assertThat(signedJWT.verify(verifier)).isTrue();
        assertClaimsPreserved(signedJWT, claimsSet);
        assertRoundTripVerification(signedJWT, verifier);
    }

    @ParameterizedTest(name = "ECDSA sign+verify – {0} / {1} (with BC provider)")
    @MethodSource("ecAlgorithmsAndCurves")
    void testSignJwtWithEcAlgorithmAndBcProvider(JWSAlgorithm algorithm, Curve curve, String curveName)
            throws Exception {
        KeyPair keyPair = ecKeyPairFor(curveName);
        JWTClaimsSet claimsSet = buildClaimsSet();

        SignedJWT signedJWT = JwsSigner.signJwt(algorithm, curve, claimsSet, keyPair.getPrivate(), KSE.BC);

        assertThat(signedJWT).isNotNull();
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(algorithm);

        ECDSAVerifier verifier = buildECDSAVerifier(curve, (ECPublicKey) keyPair.getPublic());
        assertThat(signedJWT.verify(verifier)).isTrue();
        assertClaimsPreserved(signedJWT, claimsSet);
    }

    // -----------------------------------------------------------------------
    // EdDSA – Ed25519 / EdDSA algorithm identifiers
    // RFC 8037 uses "EdDSA" while the RFC 9864 specifies "Ed25519" and deprecates "EdDSA".
    // Both must be accepted by JwsSigner.
    // -----------------------------------------------------------------------

    static Stream<Arguments> edDsaAlgorithms() {
        return Stream.of(
                Arguments.of(JWSAlgorithm.Ed25519),
                Arguments.of(JWSAlgorithm.EdDSA)
        );
    }

    @ParameterizedTest(name = "EdDSA sign+verify - {0} (no provider)")
    @MethodSource("edDsaAlgorithms")
    void testSignJwtWithEdDsaAlgorithm(JWSAlgorithm algorithm) throws Exception {
        JWTClaimsSet claimsSet = buildClaimsSet();

        SignedJWT signedJWT = JwsSigner.signJwt(algorithm, null, claimsSet,
                ed25519KeyPair.getPrivate(), null);

        assertThat(signedJWT).isNotNull();
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(algorithm);
        assertThat(signedJWT.getHeader().getKeyID()).isNull();

        BcEd25519Verifier verifier = buildEd25519Verifier();
        assertThat(signedJWT.verify(verifier)).isTrue();
        assertClaimsPreserved(signedJWT, claimsSet);
        assertRoundTripVerification(signedJWT, verifier);
    }

    @ParameterizedTest(name = "EdDSA sign+verify - {0} (with BC provider)")
    @MethodSource("edDsaAlgorithms")
    void testSignJwtWithEdDsaAlgorithmAndBcProvider(JWSAlgorithm algorithm) throws Exception {
        JWTClaimsSet claimsSet = buildClaimsSet();

        SignedJWT signedJWT = JwsSigner.signJwt(algorithm, null, claimsSet,
                ed25519KeyPair.getPrivate(), KSE.BC);

        assertThat(signedJWT).isNotNull();
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(algorithm);

        BcEd25519Verifier verifier = buildEd25519Verifier();
        assertThat(signedJWT.verify(verifier)).isTrue();
    }

    // -----------------------------------------------------------------------
    // EdDSA - Ed448 / EdDSA algorithm identifiers
    // RFC 8037 uses "EdDSA" while the RFC 9864 specifies "Ed448" and deprecates "EdDSA".
    // Both must be accepted by JwsSigner.
    // -----------------------------------------------------------------------

    static Stream<Arguments> ed448Algorithms() {
        return Stream.of(
                Arguments.of(JWSAlgorithm.Ed448),
                Arguments.of(JWSAlgorithm.EdDSA)
        );
    }

    @ParameterizedTest(name = "Ed448 sign+verify - {0} (no provider)")
    @MethodSource("ed448Algorithms")
    void testSignJwtWithEd448Algorithm(JWSAlgorithm algorithm) throws Exception {
        JWTClaimsSet claimsSet = buildClaimsSet();

        SignedJWT signedJWT = JwsSigner.signJwt(algorithm, null, claimsSet,
                ed448KeyPair.getPrivate(), null);

        assertThat(signedJWT).isNotNull();
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(algorithm);
        assertThat(signedJWT.getHeader().getKeyID()).isNull();

        BcEd448Verifier verifier = buildEd448Verifier();
        assertThat(signedJWT.verify(verifier)).isTrue();
        assertClaimsPreserved(signedJWT, claimsSet);
        assertRoundTripVerification(signedJWT, verifier);
    }

    @ParameterizedTest(name = "Ed448 sign+verify - {0} (with BC provider)")
    @MethodSource("ed448Algorithms")
    void testSignJwtWithEd448AlgorithmAndBcProvider(JWSAlgorithm algorithm) throws Exception {
        JWTClaimsSet claimsSet = buildClaimsSet();

        SignedJWT signedJWT = JwsSigner.signJwt(algorithm, null, claimsSet,
                ed448KeyPair.getPrivate(), KSE.BC);

        assertThat(signedJWT).isNotNull();
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(algorithm);

        BcEd448Verifier verifier = buildEd448Verifier();
        assertThat(signedJWT.verify(verifier)).isTrue();
    }

    // -----------------------------------------------------------------------
    // Structural / cross-algorithm tests
    // -----------------------------------------------------------------------

    @Test
    void testSignedJwtIsThreePartCompactSerialization() throws Exception {
        SignedJWT signedJWT = JwsSigner.signJwt(JWSAlgorithm.RS256, null, buildClaimsSet(),
                rsaKeyPair.getPrivate(), null);
        String compact = signedJWT.serialize();
        assertThat(compact.split("\\.")).hasSize(3);
    }

    @Test
    void testSignedJwtHeaderKeyIdIsNull() throws Exception {
        SignedJWT signedJWT = JwsSigner.signJwt(JWSAlgorithm.RS256, null, buildClaimsSet(),
                rsaKeyPair.getPrivate(), null);
        assertThat(signedJWT.getHeader().getKeyID()).isNull();
    }

    /**
     * Signing the same claims twice (even with the same key) produces different
     * serializations for ECDSA / PSS algorithms because they incorporate
     * randomness. For RS (PKCS#1 v1.5) the result is deterministic, but two
     * consecutive calls should at minimum produce structurally valid JWTs.
     */
    @Test
    void testTwoRsaSignaturesAreStructurallyValid() throws Exception {
        JWTClaimsSet claimsSet = buildClaimsSet();
        RSASSAVerifier verifier = new RSASSAVerifier((RSAPublicKey) rsaKeyPair.getPublic());

        SignedJWT first = JwsSigner.signJwt(JWSAlgorithm.RS256, null, claimsSet, rsaKeyPair.getPrivate(), null);
        SignedJWT second = JwsSigner.signJwt(JWSAlgorithm.RS256, null, claimsSet, rsaKeyPair.getPrivate(), null);

        assertThat(first.verify(verifier)).isTrue();
        assertThat(second.verify(verifier)).isTrue();
    }

    /**
     * Each EC signing operation should produce a signature that is verifiable,
     * even though ECDSA produces non-deterministic signatures.
     */
    @Test
    void testEcdsaSignaturesAreNonDeterministicButBothValid() throws Exception {
        JWTClaimsSet claimsSet = buildClaimsSet();
        ECDSAVerifier verifier = buildECDSAVerifier(Curve.P_256, (ECPublicKey) ecP256KeyPair.getPublic());

        SignedJWT first = JwsSigner.signJwt(JWSAlgorithm.ES256, Curve.P_256, claimsSet,
                ecP256KeyPair.getPrivate(), null);
        SignedJWT second = JwsSigner.signJwt(JWSAlgorithm.ES256, Curve.P_256, claimsSet,
                ecP256KeyPair.getPrivate(), null);

        assertThat(first.verify(verifier)).isTrue();
        assertThat(second.verify(verifier)).isTrue();
        // ECDSA is randomised – the two compact representations should differ
        assertThat(first.serialize()).isNotEqualTo(second.serialize());
    }

    /**
     * A signature produced with one RSA key must not verify under a different
     * RSA key.
     */
    @Test
    void testRsaSignatureDoesNotVerifyWithWrongKey() throws Exception {
        KeyPair otherKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 2048, KSE.BC);

        SignedJWT signedJWT = JwsSigner.signJwt(JWSAlgorithm.RS256, null, buildClaimsSet(),
                rsaKeyPair.getPrivate(), null);

        RSASSAVerifier wrongVerifier = new RSASSAVerifier((RSAPublicKey) otherKeyPair.getPublic());
        assertThat(signedJWT.verify(wrongVerifier)).isFalse();
    }

    /**
     * A signature produced with one EC key must not verify under a different EC
     * key on the same curve.
     */
    @Test
    void testEcdsaSignatureDoesNotVerifyWithWrongKey() throws Exception {
        KeyPair otherKeyPair = KeyPairUtil.generateECKeyPair("P-256", KSE.BC);

        SignedJWT signedJWT = JwsSigner.signJwt(JWSAlgorithm.ES256, Curve.P_256, buildClaimsSet(),
                ecP256KeyPair.getPrivate(), null);

        ECDSAVerifier wrongVerifier = buildECDSAVerifier(Curve.P_256, (ECPublicKey) otherKeyPair.getPublic());
        assertThat(signedJWT.verify(wrongVerifier)).isFalse();
    }
}


