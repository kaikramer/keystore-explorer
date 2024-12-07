package org.kse.crypto.privatekey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.kse.crypto.JwkExporter;


import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;


public class JwkPrivateKeyExporter {
    private final String alias;
    private final JwkExporter jwkExporter;

    private JwkPrivateKeyExporter(PrivateKey privateKey, String alias) {
        this.alias = alias;
        if (privateKey instanceof RSAPrivateCrtKey) {
            this.jwkExporter = new RSAPrivateKeyExporter(privateKey);
        } else {
           throw new IllegalArgumentException("Not supported key type: " + privateKey.getClass().getName());
        }
    }

    public byte[] get() throws JOSEException {
        return jwkExporter.exportWithAlias(alias);
    }

    public static JwkPrivateKeyExporter from(PrivateKey privateKey, String alias) {
        return new JwkPrivateKeyExporter(privateKey, alias);
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
