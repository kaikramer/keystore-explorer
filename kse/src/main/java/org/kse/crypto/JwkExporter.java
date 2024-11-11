package org.kse.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.kse.crypto.keypair.KeyPairUtil;

import java.security.interfaces.ECPublicKey;
import java.util.Map;
import java.util.Optional;

/**
 * Implementers knows how to export an asymmetric key
 */
public interface JwkExporter {

    /**
     * Export a {@link java.security.PublicKey} or {@link java.security.PrivateKey} instance
     *
     * @param alias a key alias
     * @return byte array with encoded key
     * @throws JOSEException thrown if export failed
     */
    byte[] exportWithAlias(String alias) throws JOSEException;

    /**
     * Checks if key can be exported
     *
     * @return true if given instance of {@link JwkExporter} can export instance of {@link java.security.PublicKey} or {@link java.security.PrivateKey}
     */
    boolean canExport();

    abstract class JwkECKeyExporter implements JwkExporter {
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

        protected Optional<Curve> getCurve(ECPublicKey publicKey) {
            try {
                String curveName = KeyPairUtil.getKeyInfo(publicKey).getDetailedAlgorithm();
                return Optional.ofNullable(supportedCurvesMap.get(curveName));
            } catch (CryptoException e) {
                return Optional.empty();
            }
        }
    }

    abstract class JwkEdDSAKeyExporter implements JwkExporter {
        protected final Map<String, Curve> supportedCurvesMap =
                Map.of(
                        "Ed25519", Curve.Ed25519,
                        "Ed448", Curve.Ed448
                );

        protected Optional<Curve> getCurve(BCEdDSAPublicKey bcEdDSAPublicKey) {
            return Optional.ofNullable(supportedCurvesMap.get(bcEdDSAPublicKey.getAlgorithm()));
        }
    }

    class NotSupportedKeyTypeExporter implements JwkExporter {
        @Override
        public byte[] exportWithAlias(String alias) {
            return new byte[0];
        }

        @Override
        public boolean canExport() {
            return false;
        }
    }
}
