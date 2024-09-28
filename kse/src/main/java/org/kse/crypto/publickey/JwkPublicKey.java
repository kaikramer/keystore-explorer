package org.kse.crypto.publickey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

public class JwkPublicKey {
    private final PublicKey publicKey;
    private final String alias;

    private JwkPublicKey(PublicKey publicKey, String alias) {
        this.publicKey = publicKey;
        this.alias = alias;
    }

    public static JwkPublicKey from(PublicKey publicKey, String alias) {
        return new JwkPublicKey(publicKey, alias);
    }

    public byte[] get() throws JOSEException {
        if (publicKey instanceof ECPublicKey) {
            return new ECPublicKeyExporter(publicKey).exportWithAlias(alias);
        } else {
            return new byte[0];
        }
    }

    public static class ECPublicKeyExporter {
        private final ECPublicKey ecPublicKey;

        ECPublicKeyExporter(PublicKey ecPublicKey) {
            this.ecPublicKey = (ECPublicKey) ecPublicKey;
        }

        public static Curve mapJavaECCurveToNimbus(AlgorithmParameterSpec algorithmParameterSpec) {
            if (algorithmParameterSpec instanceof ECNamedCurveSpec) {
                String name = ((ECNamedCurveSpec) algorithmParameterSpec).getName();
                Curve curve;
                switch (name) {
                    case "prime256v1":
                    case "secp256r1":
                        curve =  Curve.P_256;
                        break;
                    case "secp256k1":
                        curve =  Curve.SECP256K1;
                        break;
                    case "secp384r1":
                        curve = Curve.P_384;
                        break;
                    case "secp521r1":
                        curve =  Curve.P_521;
                        break;
                    case "Ed2559":
                        curve =  Curve.Ed25519;
                        break;
                    case "Ed2448":
                        curve =  Curve.Ed448;
                        break;
                    default:
                        curve = Curve.parse(name);
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
            ECKey.Builder builder = new ECKey.Builder(curve, ecPublicKey)
                    .keyUse(KeyUse.SIGNATURE);
            if (alias != null) {
                builder.keyID(alias);
            } else {
                builder.keyIDFromThumbprint();
            }
            ECKey ecKey = builder.build();
            return ecKey.toJSONString().getBytes(StandardCharsets.UTF_8);
        }
    }
}
