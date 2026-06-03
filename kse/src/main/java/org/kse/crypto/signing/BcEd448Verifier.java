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

import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed448Signer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * Ed448 verifier backed by Bouncy Castle.
 */
public class BcEd448Verifier extends BaseJWSProvider implements JWSVerifier {

    private static final Set<JWSAlgorithm> SUPPORTED = Set.of(JWSAlgorithm.Ed448, JWSAlgorithm.EdDSA);
    private static final byte[] NO_CONTEXT = new byte[0];

    private final Ed448PublicKeyParameters publicKeyParams;

    public BcEd448Verifier(OctetKeyPair publicKey) throws JOSEException {
        super(SUPPORTED);
        publicKeyParams = new Ed448PublicKeyParameters(publicKey.getDecodedX(), 0);
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!SUPPORTED.contains(alg)) {
            throw new JOSEException("Unsupported algorithm: " + alg);
        }
        try {
            // RFC 8037/9864 do not allow for Ed448 with context
            Ed448Signer verifier = new Ed448Signer(NO_CONTEXT);
            verifier.init(false, publicKeyParams);
            verifier.update(signingInput, 0, signingInput.length);
            return verifier.verifySignature(signature.decode());
        } catch (Exception e) {
            throw new JOSEException("Ed448 verification failed: " + e.getMessage(), e);
        }
    }
}
