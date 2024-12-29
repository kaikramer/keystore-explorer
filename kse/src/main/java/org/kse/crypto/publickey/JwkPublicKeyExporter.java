package org.kse.crypto.publickey;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.kse.crypto.JwkExporter;

public class JwkPublicKeyExporter {
    private final String alias;
    private final JwkExporter jwkExporter;

    private JwkPublicKeyExporter(PublicKey publicKey, String alias) {
        this.alias = alias;
        if (publicKey instanceof ECPublicKey) {
            this.jwkExporter = new JwkECPublicKeyExporter(publicKey);
        } else if (publicKey instanceof BCEdDSAPublicKey) {
            this.jwkExporter = new JwkEdDSAPublicKeyExporter(publicKey);
        } else if (publicKey instanceof RSAPublicKey) {
            this.jwkExporter = new RSAPublicKeyExporter(publicKey);
        } else {
            this.jwkExporter = new JwkExporter.NotSupportedKeyTypeExporter();
        }
    }

    public static JwkPublicKeyExporter from(PublicKey publicKey, String alias) {
        return new JwkPublicKeyExporter(publicKey, alias);
    }

    public boolean canExport() {
        return this.jwkExporter.canExport();
    }

    public byte[] get() throws JOSEException {
        return jwkExporter.exportWithAlias(alias);
    }

    private static class JwkEdDSAPublicKeyExporter extends JwkExporter.JwkEdKeyExporter {
        private final BCEdDSAPublicKey bcEdDSAPublicKey;

        JwkEdDSAPublicKeyExporter(PublicKey publicKey) {
            this.bcEdDSAPublicKey = (BCEdDSAPublicKey) publicKey;
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
        public boolean canExport() {
            return getCurve(bcEdDSAPublicKey).isPresent();
        }
    }

    private static class JwkECPublicKeyExporter extends JwkExporter.JwkECKeyExporter {

        private final ECPublicKey ecPublicKey;

        JwkECPublicKeyExporter(PublicKey ecPublicKey) {
            this.ecPublicKey = (ECPublicKey) ecPublicKey;
        }

        public byte[] exportWithAlias(String alias) throws JOSEException {
            Optional<Curve> curve = getCurve(ecPublicKey);
            if (curve.isEmpty()) {
                return new byte[0];
            }
            ECKey.Builder builder = new ECKey.Builder(curve.get(), ecPublicKey);
            if (alias != null) {
                builder.keyID(alias);
            } else {
                builder.keyIDFromThumbprint();
            }
            ECKey ecKey = builder.build();
            return ecKey.toJSONString().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean canExport() {
            return getCurve(ecPublicKey).isPresent();
        }
    }

    private static class RSAPublicKeyExporter implements JwkExporter {
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
        public boolean canExport() {
            return true;
        }
    }
}