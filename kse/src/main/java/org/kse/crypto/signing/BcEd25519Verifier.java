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

import java.util.Set;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * Ed25519 verifier backed by Bouncy Castle, replacing the Tink-dependent nimbus {@code Ed25519Verifier}.
 */
public class BcEd25519Verifier extends BaseJWSProvider implements JWSVerifier {

    private static final Set<JWSAlgorithm> SUPPORTED = Set.of(JWSAlgorithm.Ed25519, JWSAlgorithm.EdDSA);

    private final Ed25519PublicKeyParameters publicKeyParams;

    public BcEd25519Verifier(OctetKeyPair publicKey) throws JOSEException {
        super(SUPPORTED);
        publicKeyParams = new Ed25519PublicKeyParameters(publicKey.getDecodedX(), 0);
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!SUPPORTED.contains(alg)) {
            throw new JOSEException("Unsupported algorithm: " + alg);
        }
        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, publicKeyParams);
            verifier.update(signingInput, 0, signingInput.length);
            return verifier.verifySignature(signature.decode());
        } catch (Exception e) {
            throw new JOSEException("Ed25519 verification failed: " + e.getMessage(), e);
        }
    }
}
