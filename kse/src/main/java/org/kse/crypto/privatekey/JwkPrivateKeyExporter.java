package org.kse.crypto.privatekey;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECPoint;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.kse.crypto.JwkExporter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

public class JwkPrivateKeyExporter {
    private final String alias;
    private final JwkExporter jwkExporter;

    private JwkPrivateKeyExporter(PrivateKey privateKey, String alias) {
        this.alias = alias;
        if (privateKey instanceof RSAPrivateCrtKey) {
            this.jwkExporter = new RSAPrivateKeyExporter(privateKey);
        } else if (privateKey instanceof ECPrivateKey) {
            this.jwkExporter = new ECPrivateKeyExporter(privateKey);
        } else if (privateKey instanceof BCEdDSAPrivateKey) {
            this.jwkExporter = new EdDSAPrivatKeyExporter(privateKey);
        } else {
            throw new IllegalArgumentException("Not supported key type: " + privateKey.getClass().getName());
        }
    }

    public static JwkPrivateKeyExporter from(PrivateKey privateKey, String alias) {
        return new JwkPrivateKeyExporter(privateKey, alias);
    }

    public byte[] get() throws JOSEException {
        return jwkExporter.exportWithAlias(alias);
    }

    private static class EdDSAPrivatKeyExporter extends JwkExporter.EdDSAKeyExporter {
        private final BCEdDSAPrivateKey privateKey;

        private EdDSAPrivatKeyExporter(PrivateKey privateKey) {
            this.privateKey = (BCEdDSAPrivateKey) privateKey;
        }

        @Override
        public byte[] exportWithAlias(String alias) throws JOSEException {
            Optional<Curve> maybeCurve = getCurve(privateKey);
            if (maybeCurve.isEmpty()) {
                return new byte[0];
            }
            Curve curve = maybeCurve.get();
            EdDSAPublicKey edDSAPublicKey = privateKey.getPublicKey();
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(edDSAPublicKey.getEncoded());
            byte[] rawKey = subjectPublicKeyInfo.getPublicKeyData().getBytes();
            OctetKeyPair.Builder builder = new OctetKeyPair.Builder(curve, Base64URL.encode(rawKey));
            try {
                ASN1Primitive privateKeyOctetString = DEROctetString.fromByteArray(
                        PrivateKeyInfo.getInstance(privateKey.getEncoded()).getPrivateKey().getOctets());
                byte[] d = DEROctetString.getInstance(privateKeyOctetString.getEncoded()).getOctets();
                builder.d(Base64URL.encode(d));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            if (alias != null) {
                builder.keyID(alias);
            } else {
                builder.keyIDFromThumbprint();
            }
            OctetKeyPair key = builder.build();
            return key.toJSONString().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean canExport() {
            return true;
        }
    }

    private static class ECPrivateKeyExporter extends JwkExporter.ECKeyExporter {
        private final ECPrivateKey privateKey;

        private ECPrivateKeyExporter(PrivateKey privateKey) {
            this.privateKey = (ECPrivateKey) privateKey;
        }

        @Override
        public byte[] exportWithAlias(String alias) throws JOSEException {
            Optional<Curve> curve = getCurve(this.privateKey);
            if (curve.isEmpty()) {
                return new byte[0];
            }
            final ECPoint generator = this.privateKey.getParams().getGenerator();
            ECKey.Builder builder = new ECKey.Builder(curve.get(), Base64URL.encode(generator.getAffineX()),
                                                      Base64URL.encode(generator.getAffineY()));
            builder.d(Base64URL.encode(this.privateKey.getS()));
            if (alias != null) {
                builder.keyID(alias);
            } else {
                builder.keyIDFromThumbprint();
            }
            ECKey key = builder.build();
            return key.toJSONString().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean canExport() {
            return true;
        }
    }

    private static class RSAPrivateKeyExporter implements JwkExporter {
        private final RSAPrivateCrtKey privateKey;

        private RSAPrivateKeyExporter(PrivateKey privateKey) {
            this.privateKey = (RSAPrivateCrtKey) privateKey;
        }

        @Override
        public byte[] exportWithAlias(String alias) throws JOSEException {
            final var n = Base64URL.encode(this.privateKey.getModulus().toByteArray());
            final var e = Base64URL.encode(this.privateKey.getPublicExponent().toByteArray());
            RSAKey.Builder builder = new RSAKey.Builder(n, e);
            if (alias != null) {
                builder.keyID(alias);
            } else {
                builder.keyIDFromThumbprint();
            }
            builder.privateKey(privateKey);
            RSAKey rsaKey = builder.build();
            return rsaKey.toJSONString().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean canExport() {
            return true;
        }
    }
}
