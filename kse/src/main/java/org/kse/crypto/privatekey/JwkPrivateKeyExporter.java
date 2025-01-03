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
package org.kse.crypto.privatekey;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECPoint;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.kse.crypto.jwk.JwkExporter;
import org.kse.crypto.jwk.JwkExporterException;

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
            this.jwkExporter = new EdDSAPrivateKeyExporter(privateKey);
        } else {
            throw new IllegalArgumentException("Not supported key type: " + privateKey.getClass().getName());
        }
    }

    public static JwkPrivateKeyExporter from(PrivateKey privateKey, String alias) {
        return new JwkPrivateKeyExporter(privateKey, alias);
    }

    public byte[] get() {
        return jwkExporter.exportWithAlias(alias);
    }

    private static class EdDSAPrivateKeyExporter extends JwkExporter.EdDSAKeyExporter {
        private final BCEdDSAPrivateKey privateKey;

        private EdDSAPrivateKeyExporter(PrivateKey privateKey) {
            this.privateKey = (BCEdDSAPrivateKey) privateKey;
        }

        @Override
        public byte[] exportWithAlias(String alias) {
            Curve curve = getCurve(privateKey);
            try {
                EdDSAPublicKey edDSAPublicKey = privateKey.getPublicKey();
                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                        edDSAPublicKey.getEncoded());
                byte[] rawKey = subjectPublicKeyInfo.getPublicKeyData().getBytes();
                OctetKeyPair.Builder builder = new OctetKeyPair.Builder(curve, Base64URL.encode(rawKey));
                ASN1Primitive privateKeyOctetString = DEROctetString.fromByteArray(
                        PrivateKeyInfo.getInstance(privateKey.getEncoded()).getPrivateKey().getOctets());
                byte[] d = DEROctetString.getInstance(privateKeyOctetString.getEncoded()).getOctets();
                builder.d(Base64URL.encode(d));
                if (alias != null) {
                    builder.keyID(alias);
                } else {
                    builder.keyIDFromThumbprint();
                }
                OctetKeyPair key = builder.build();
                return key.toJSONString().getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw JwkExporterException.keyExportFailed(alias, e);
            }
        }
    }

    private static class ECPrivateKeyExporter extends JwkExporter.ECKeyExporter {
        private final ECPrivateKey privateKey;

        private ECPrivateKeyExporter(PrivateKey privateKey) {
            this.privateKey = (ECPrivateKey) privateKey;
        }

        @Override
        public byte[] exportWithAlias(String alias) {
            Curve curve = getCurve(this.privateKey);
            try {
                final ECPoint generator = this.privateKey.getParams().getGenerator();
                ECKey.Builder builder = new ECKey.Builder(curve, Base64URL.encode(generator.getAffineX()),
                                                          Base64URL.encode(generator.getAffineY()));
                builder.d(Base64URL.encode(this.privateKey.getS()));
                if (alias != null) {
                    builder.keyID(alias);
                } else {
                    builder.keyIDFromThumbprint();
                }
                ECKey key = builder.build();
                return key.toJSONString().getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw JwkExporterException.keyExportFailed(alias, e);
            }
        }
    }

    private static class RSAPrivateKeyExporter implements JwkExporter {
        private final RSAPrivateCrtKey privateKey;

        private RSAPrivateKeyExporter(PrivateKey privateKey) {
            this.privateKey = (RSAPrivateCrtKey) privateKey;
        }

        @Override
        public byte[] exportWithAlias(String alias) {
            try {
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
            } catch (Exception e) {
                throw JwkExporterException.keyExportFailed(alias, e);
            }
        }
    }
}
