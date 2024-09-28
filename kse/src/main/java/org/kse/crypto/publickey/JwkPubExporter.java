package org.kse.crypto.publickey;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

public class JwkPubExporter {
    private final PublicKey publicKey;
    private final String alias;

    private JwkPubExporter(PublicKey publicKey, String alias) {
        this.publicKey = publicKey;
        this.alias = alias;
    }

    public static JwkPubExporter from(PublicKey publicKey, String alias) {
        return new JwkPubExporter(publicKey, alias);
    }

    public byte[] get() throws JOSEException {
        if (publicKey instanceof ECPublicKey) {
            return new ECPublicKeyExporter(publicKey).exportWithAlias(alias);
        } else if (publicKey instanceof RSAPublicKey) {
            return new RSAPublicKeyExporter(publicKey).exportWithAlias(alias);
        }
        throw new IllegalArgumentException("Unsupported public key type");
    }

    private static class ECPublicKeyExporter {
        private final ECPublicKey ecPublicKey;

        ECPublicKeyExporter(PublicKey ecPublicKey) {
            this.ecPublicKey = (ECPublicKey) ecPublicKey;
        }

        public static Curve mapJavaECCurveToNimbus(AlgorithmParameterSpec algorithmParameterSpec) {
            if (algorithmParameterSpec instanceof ECNamedCurveSpec) {
                String name = ((ECNamedCurveSpec) algorithmParameterSpec).getName();
                Curve curve = null;
                switch (name) {
                case "prime256v1":
                case "secp256r1":
                    curve = Curve.P_256;
                    break;
                case "secp256k1":
                    curve = Curve.SECP256K1;
                    break;
                case "secp384r1":
                    curve = Curve.P_384;
                    break;
                case "secp521r1":
                    curve = Curve.P_521;
                    break;
                case "Ed2559":
                    curve = Curve.Ed25519;
                    break;
                case "Ed2448":
                    curve = Curve.Ed448;
                    break;
                default:
                    break;
                }
                if (curve == null) {
                    throw new IllegalArgumentException(String.format("Unsupported EC curve \"%s\"", name));
                }
                return curve;
            } else {
                throw new IllegalArgumentException("Named curve required");
            }
        }

        public byte[] exportWithAlias(String alias) throws JOSEException {
            ECParameterSpec ecParameterSpec = ecPublicKey.getParams();
            Curve curve = mapJavaECCurveToNimbus(ecParameterSpec);
            ECKey.Builder builder = new ECKey.Builder(curve, ecPublicKey).keyUse(KeyUse.SIGNATURE);
            if (alias != null) {
                builder.keyID(alias);
            } else {
                builder.keyIDFromThumbprint();
            }
            ECKey ecKey = builder.build();
            return ecKey.toJSONString().getBytes(StandardCharsets.UTF_8);
        }
    }

    private static class RSAPublicKeyExporter {
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
    }
}