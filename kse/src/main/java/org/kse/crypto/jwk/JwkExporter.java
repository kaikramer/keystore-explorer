/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
package org.kse.crypto.jwk;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.kse.crypto.CryptoException;
import org.kse.crypto.keypair.KeyPairUtil;

import com.nimbusds.jose.jwk.Curve;

/**
 * Implementers knows how to export an asymmetric key
 */
public interface JwkExporter {

    /**
     * Export a {@link java.security.PublicKey} or {@link java.security.PrivateKey} instance
     *
     * @param alias a key alias
     * @return byte array with encoded key
     */
    byte[] exportWithAlias(String alias);

    abstract class ECKeyExporter implements JwkExporter {
        protected static final Map<String, Curve> supportedCurvesMap =
                Map.of(
                        "prime256v1", Curve.P_256,
                        "secp256r1", Curve.P_256,
                        "P-256", Curve.P_256,
                        "secp256k1", Curve.SECP256K1,
                        "secp384r1", Curve.P_384,
                        "P-384", Curve.P_384,
                        "secp521r1", Curve.P_521,
                        "P-521", Curve.P_521
                );

        public static boolean supportsCurve(String curveName) {
            return supportedCurvesMap.containsKey(curveName);
        }
        protected Curve getCurve(ECPrivateKey privateKey) {
            try {
                String curveName = KeyPairUtil.getKeyInfo(privateKey).getDetailedAlgorithm();
                return supportedCurvesMap.get(curveName);
            } catch (CryptoException e) {
                throw JwkExporterException.notSupported(privateKey.getAlgorithm(), e);
            }
        }

        protected Curve getCurve(ECPublicKey publicKey) {
            try {
                String curveName = KeyPairUtil.getKeyInfo(publicKey).getDetailedAlgorithm();
                return supportedCurvesMap.get(curveName);
            } catch (CryptoException e) {
                throw JwkExporterException.notSupported(publicKey.getAlgorithm(), e);
            }
        }
    }

    abstract class EdDSAKeyExporter implements JwkExporter {
        protected final Map<String, Curve> supportedCurvesMap =
                Map.of(
                        "Ed25519", Curve.Ed25519,
                        "Ed448", Curve.Ed448
                );

        protected Curve getCurve(BCEdDSAPublicKey bcEdDSAPublicKey) {
            return supportedCurvesMap.get(bcEdDSAPublicKey.getAlgorithm());
        }

        protected Curve getCurve(BCEdDSAPrivateKey bcEdDSAPrivateKey) {
            return supportedCurvesMap.get(bcEdDSAPrivateKey.getAlgorithm());
        }
    }
}
