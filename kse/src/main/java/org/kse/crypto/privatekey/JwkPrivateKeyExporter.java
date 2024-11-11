package org.kse.crypto.privatekey;

import com.nimbusds.jose.JOSEException;
import org.kse.crypto.JwkExporter;


import java.security.PrivateKey;

public class JwkPrivateKeyExporter {
    private final String alias;
    private final JwkExporter jwkExporter;

    private JwkPrivateKeyExporter(PrivateKey privateKey, String alias) {
        this.alias = alias;
        this.jwkExporter = new JwkExporter.NotSupportedKeyTypeExporter();
    }

    public boolean canExport() {
        return this.jwkExporter.canExport();
    }

    public byte[] get() throws JOSEException {
        return jwkExporter.exportWithAlias(alias);
    }

    public static JwkPrivateKeyExporter from(PrivateKey privateKey, String alias) {
        return new JwkPrivateKeyExporter(privateKey, alias);
    }
}
