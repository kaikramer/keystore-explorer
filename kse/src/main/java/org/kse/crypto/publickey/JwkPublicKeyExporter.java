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
package org.kse.crypto.publickey;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.jwk.JwkExporter;
import org.kse.crypto.jwk.JwkExporterException;
import org.kse.crypto.keypair.KeyPairUtil;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

public class JwkPublicKeyExporter {
    private final String alias;
    private final JwkExporter jwkExporter;

    private JwkPublicKeyExporter(PublicKey publicKey, String alias) {
        this.alias = alias;
        if (publicKey instanceof ECPublicKey) {
            this.jwkExporter = new JwkPublicKeyExporter.ECPublicKeyExporter(publicKey);
        } else if (publicKey instanceof BCEdDSAPublicKey) {
            this.jwkExporter = new JwkPublicKeyExporter.EdDSAPublicKeyExporter(publicKey);
        } else if (publicKey instanceof RSAPublicKey) {
            this.jwkExporter = new JwkPublicKeyExporter.RSAPublicKeyExporter(publicKey);
        } else {
            throw JwkExporterException.notSupported(publicKey.getAlgorithm(), null);
        }
    }

    public static JwkPublicKeyExporter from(PublicKey publicKey, String alias) {
        return new JwkPublicKeyExporter(publicKey, alias);
    }

    public static boolean isPublicKeyTypeExportable(PublicKey publicKey)  {
        try {
            switch (KeyPairUtil.getKeyPairType(publicKey)) {
            case ED448:
            case ED25519:
            case RSA:
                return true;
            case EC:
                KeyInfo keyInfo = KeyPairUtil.getKeyInfo(publicKey);
                String detailedAlgorithm = keyInfo.getDetailedAlgorithm();
                return JwkExporter.ECKeyExporter.supportsCurve(detailedAlgorithm);
            default:
                return false;
            }
        } catch (Exception e) {
            throw JwkExporterException.notSupported(publicKey.getAlgorithm(), null);
        }
    }

    public byte[] get() {
        return jwkExporter.exportWithAlias(alias);
    }

    private static class EdDSAPublicKeyExporter extends JwkExporter.EdDSAKeyExporter {
        private final BCEdDSAPublicKey bcEdDSAPublicKey;

        EdDSAPublicKeyExporter(PublicKey publicKey) {
            this.bcEdDSAPublicKey = (BCEdDSAPublicKey) publicKey;
        }

        @Override
        public byte[] exportWithAlias(String alias) {
            Curve curve = getCurve(bcEdDSAPublicKey);
            try {
                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                        bcEdDSAPublicKey.getEncoded());
                byte[] rawKey = subjectPublicKeyInfo.getPublicKeyData().getBytes();
                OctetKeyPair.Builder builder = new OctetKeyPair.Builder(curve, Base64URL.encode(rawKey));
                if (alias != null) {
                    builder.keyID(alias);
                } else {
                    builder.keyIDFromThumbprint();
                }
                OctetKeyPair key = builder.build();
                return key.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw JwkExporterException.keyExportFailed(alias, e);
            }
        }
    }

    private static class ECPublicKeyExporter extends JwkExporter.ECKeyExporter {
        private final ECPublicKey ecPublicKey;

        ECPublicKeyExporter(PublicKey ecPublicKey) {
            this.ecPublicKey = (ECPublicKey) ecPublicKey;
        }

        @Override
        public byte[] exportWithAlias(String alias) {
            Curve curve = getCurve(ecPublicKey);
            try {
                ECKey.Builder builder = new ECKey.Builder(curve, ecPublicKey);
                if (alias != null) {
                    builder.keyID(alias);
                } else {
                    builder.keyIDFromThumbprint();
                }
                ECKey ecKey = builder.build();
                return ecKey.toJSONString().getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw JwkExporterException.keyExportFailed(alias, e);
            }
        }
    }

    private static class RSAPublicKeyExporter implements JwkExporter {
        private final RSAPublicKey rsaPublicKey;

        public RSAPublicKeyExporter(PublicKey publicKey) {
            this.rsaPublicKey = (RSAPublicKey) publicKey;
        }

        public byte[] exportWithAlias(String alias) {
            try {
                RSAKey.Builder builder = new RSAKey.Builder(rsaPublicKey);
                if (alias != null) {
                    builder.keyID(alias);
                } else {
                    builder.keyIDFromThumbprint();
                }
                RSAKey rsaKey = builder.build();
                return rsaKey.toJSONString().getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw JwkExporterException.keyExportFailed(alias, e);
            }
        }
    }
}
