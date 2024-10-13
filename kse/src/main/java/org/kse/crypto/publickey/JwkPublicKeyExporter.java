package org.kse.crypto.publickey;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Map;
import java.util.Optional;

import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;

public class JwkPublicKeyExporter {
    private final String alias;
    private final KeyExporter keyExporter;

    private JwkPublicKeyExporter(PublicKey publicKey, String alias) {
        this.alias = alias;
        if (publicKey instanceof ECPublicKey) {
            this.keyExporter = new ECPublicKeyExporter(publicKey);
        } else if (publicKey instanceof BCEdDSAPublicKey) {
            this.keyExporter = new EdDSAPublicKeyExporter(publicKey);
        } else if (publicKey instanceof RSAPublicKey) {
            this.keyExporter = new RSAPublicKeyExporter(publicKey);
        } else {
            this.keyExporter = new NotSupportedKeyTypeExporter();
        }
    }

    public static JwkPublicKeyExporter from(PublicKey publicKey, String alias) {
        return new JwkPublicKeyExporter(publicKey, alias);
    }

    public boolean canExport() {
        return this.keyExporter.supportsKey();
    }

    public byte[] get() throws JOSEException {
        return keyExporter.exportWithAlias(alias);
    }

    interface KeyExporter {
        byte[] exportWithAlias(String alias) throws JOSEException;

        boolean supportsKey();
    }

    private static class NotSupportedKeyTypeExporter implements KeyExporter {
        @Override
        public byte[] exportWithAlias(String alias) {
            return new byte[0];
        }

        @Override
        public boolean supportsKey() {
            return false;
        }
    }

    private static class EdDSAPublicKeyExporter implements KeyExporter {
        private final BCEdDSAPublicKey bcEdDSAPublicKey;
        private static final Map<String, Curve> supportedCurvesMap =
                Map.of(
                        "Ed25519", Curve.Ed25519,
                        "Ed448", Curve.Ed448
                );

        EdDSAPublicKeyExporter(PublicKey publicKey) {
            this.bcEdDSAPublicKey = (BCEdDSAPublicKey) publicKey;
        }

        private Optional<Curve> getCurve(BCEdDSAPublicKey bcEdDSAPublicKey) {
            return Optional.ofNullable(supportedCurvesMap.get(bcEdDSAPublicKey.getAlgorithm()));
        }

        @Override
        public byte[] exportWithAlias(String alias) throws JOSEException {
            Optional<Curve> maybeCurve = getCurve(bcEdDSAPublicKey);
            if (maybeCurve.isEmpty()) {
                return new byte[0];
            }
            Curve curve = maybeCurve.get();
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(bcEdDSAPublicKey.getEncoded());
            byte[] rawKey = subjectPublicKeyInfo.getPublicKeyData().getBytes();
            OctetKeyPair.Builder builder = new OctetKeyPair.Builder(
                    curve,
                    Base64URL.encode(rawKey)
            );
            if (alias != null) {
                builder.keyID(alias);
            } else {
                builder.keyIDFromThumbprint();
            }
            OctetKeyPair key = builder.build();
            return key.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean supportsKey() {
            return getCurve(bcEdDSAPublicKey).isPresent();
        }
    }

    private static class ECPublicKeyExporter implements KeyExporter {
        private static final Map<String, Curve> supportedCurvesMap =
                Map.of(
                        "prime256v1", Curve.P_256,
                        "secp256r1", Curve.P_256,
                        "NIST P-256", Curve.P_256,
                        "secp256k1", Curve.SECP256K1,
                        "secp384r1", Curve.P_384,
                        "NIST P-384", Curve.P_384,
                        "secp521r1", Curve.P_521,
                        "NIST P-521", Curve.P_521
                );

        private final ECPublicKey ecPublicKey;

        ECPublicKeyExporter(PublicKey ecPublicKey) {
            this.ecPublicKey = (ECPublicKey) ecPublicKey;
        }

        private Optional<Curve> getCurve(ECPublicKey publicKey) {
            ECParameterSpec ecParameterSpec = publicKey.getParams();
            if (!(ecParameterSpec instanceof ECNamedCurveSpec)) {
                return Optional.empty();
            }
            String curveName = ((ECNamedCurveSpec) ecParameterSpec).getName();
            return Optional.ofNullable(supportedCurvesMap.get(curveName));
        }

        private boolean canExport(ECPublicKey ecPublicKey) {
            return getCurve(ecPublicKey).isPresent();
        }

        public byte[] exportWithAlias(String alias) throws JOSEException {
            Optional<Curve> maybeCurve = getCurve(ecPublicKey);
            if (maybeCurve.isEmpty()) {
                return new byte[0];
            }
            Curve curve = maybeCurve.get();
            ECKey.Builder builder = new ECKey.Builder(curve, ecPublicKey);
            if (alias != null) {
                builder.keyID(alias);
            } else {
                builder.keyIDFromThumbprint();
            }
            ECKey ecKey = builder.build();
            return ecKey.toJSONString().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean supportsKey() {
            return canExport(ecPublicKey);
        }
    }

    private static class RSAPublicKeyExporter implements KeyExporter {
        private final RSAPublicKey rsaPublicKey;

        public RSAPublicKeyExporter(PublicKey publicKey) {
            this.rsaPublicKey = (RSAPublicKey) publicKey;
        }

        public byte[] exportWithAlias(String alias) throws JOSEException {
            RSAKey.Builder builder = new RSAKey.Builder(rsaPublicKey);
            if (alias != null) {
                builder.keyID(alias);
            } else {
                builder.keyIDFromThumbprint();
            }
            RSAKey rsaKey = builder.build();
            return rsaKey.toJSONString().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean supportsKey() {
            return true;
        }
    }
}