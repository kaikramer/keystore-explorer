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

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * Ed25519 signer backed by Bouncy Castle, replacing the Tink-dependent nimbus {@code Ed25519Signer}.
 */
public class BcEd25519Signer extends BaseJWSProvider implements JWSSigner {

    private static final Set<JWSAlgorithm> SUPPORTED = Set.of(JWSAlgorithm.Ed25519, JWSAlgorithm.EdDSA);

    private final Ed25519PrivateKeyParameters privateKeyParams;

    public BcEd25519Signer(OctetKeyPair privateKey) throws JOSEException {
        super(SUPPORTED);
        if (!privateKey.isPrivate()) {
            throw new JOSEException("OctetKeyPair must contain a private key (d)");
        }
        privateKeyParams = new Ed25519PrivateKeyParameters(privateKey.getDecodedD(), 0);
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!SUPPORTED.contains(alg)) {
            throw new JOSEException("Unsupported algorithm: " + alg);
        }
        try {
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(true, privateKeyParams);
            signer.update(signingInput, 0, signingInput.length);
            return Base64URL.encode(signer.generateSignature());
        } catch (Exception e) {
            throw new JOSEException("Ed25519 signing failed: " + e.getMessage(), e);
        }
    }
}
