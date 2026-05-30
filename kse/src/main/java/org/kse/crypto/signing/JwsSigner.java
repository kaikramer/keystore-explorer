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

import java.security.PrivateKey;
import java.security.Provider;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Utility class for signing JWTs.
 */
public class JwsSigner {

    private JwsSigner() {
    }

    /**
     * Signs a JWT with the specified parameters.
     *
     * @param curve              The elliptic curve to use for EC signatures.
     * @param signatureAlgorithm The JWS algorithm to use for signing.
     * @param claimsSet          The JWT claims set to sign.
     * @param privateKey         The private key to use for signing.
     * @param provider           The security provider to use (can be null).
     * @return A SignedJWT object representing the signed JWT.
     * @throws Exception If an error occurs during signing.
     */
    public static SignedJWT signJwt(JWSAlgorithm signatureAlgorithm, com.nimbusds.jose.jwk.Curve curve,
                                    JWTClaimsSet claimsSet, PrivateKey privateKey, Provider provider) throws Exception {
        JWSSigner signer = null;

        if (JWSAlgorithm.Family.RSA.contains(signatureAlgorithm)) {
            signer = new RSASSASigner(privateKey);
        } else if (JWSAlgorithm.Family.EC.contains(signatureAlgorithm)) {
            signer = new ECDSASigner(privateKey, curve);
        } else if (JWSAlgorithm.Ed25519 == signatureAlgorithm || JWSAlgorithm.EdDSA == signatureAlgorithm) {
            var params = (Ed25519PrivateKeyParameters) PrivateKeyFactory.createKey(privateKey.getEncoded());
            OctetKeyPair okp = buildOctectKeyAPair(params);
            signer = new BcEd25519Signer(okp);
        }

        if (provider != null && signer != null) {
            signer.getJCAContext().setProvider(provider);
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(signatureAlgorithm).keyID(null).build(), claimsSet);
        signedJWT.sign(signer);

        return signedJWT;
    }

    private static OctetKeyPair buildOctectKeyAPair(Ed25519PrivateKeyParameters params) {
        Base64URL base64EncodedPubKey = Base64URL.encode(params.generatePublicKey().getEncoded());
        Base64URL base64EncodedParams = Base64URL.encode(params.getEncoded());
        return new OctetKeyPair.Builder(Curve.Ed25519, base64EncodedPubKey).d(base64EncodedParams).build();
    }
}
