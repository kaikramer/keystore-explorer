/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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
package org.kse.crypto.jwk;

import static org.kse.crypto.privatekey.EncryptionType.ENCRYPTED;
import static org.kse.crypto.privatekey.EncryptionType.UNENCRYPTED;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;
import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.privatekey.EncryptionType;
import org.kse.crypto.privatekey.PrivateKeyEncryptedException;
import org.kse.crypto.privatekey.PrivateKeyUnencryptedException;
import org.kse.crypto.publickey.OpenSslPubUtil;
import org.kse.gui.passwordmanager.Password;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

/**
 * Provides utility methods relating to JWK encoded keys.
 */
public class JwkUtil {

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/privatekey/resources");

    private static final int PBES2_SALT_LENGTH = 16;
    private static final int PBES2_ITERATION_COUNT = 10000;

    // Utility pattern
    private JwkUtil() {
    }

    /**
     * JWK encode a public key.
     *
     * @param publicKey The public key.
     * @param alias     The entry alias. Used for the JWK keyId. If null, then the JWK thumbprint is
     *                  used for the JWK keyId.
     * @return The JWK encoded public key.
     */
    public static String get(PublicKey publicKey, String alias) {
        JwkExporter jwkExporter;

        if (publicKey instanceof RSAPublicKey) {
            jwkExporter = new RSAKeyExporter(publicKey);
        } else if (publicKey instanceof ECPublicKey) {
            jwkExporter = new ECKeyExporter(publicKey);
        } else {
            jwkExporter = checkForJdkEdDSA(publicKey);

            if (jwkExporter == null) {
                // Don't bother to translate this exception. This condition will never be encountered
                // since DExportPrivateKeyType.isJwkSupported and JwkPublicKeyExporter.isPublicKeyTypeExportable
                // guard the UI to prevent calling this method for unsupported key types.
                throw new IllegalArgumentException("Not supported key type: " + publicKey.getClass().getName());
            }
        }

        return jwkExporter.export(alias, null);
    }

    /**
     * JWK encode a private key.
     *
     * @param privateKey The private key.
     * @param alias      The entry alias. Used for the JWK keyId. If null, then the JWK thumbprint is
     *                   used for the JWK keyId.
     * @return The JWK encoded private key.
     */
    public static String get(PrivateKey privateKey, String alias) {
        return get(privateKey, alias, null);
    }

    /**
     * JWK encode a key pair with certificate.
     *
     * @param privateKey The private key.
     * @param alias      The entry alias. Used for the JWK keyId. If null, then the JWK thumbprint is
     *                   used for the JWK keyId.
     * @param chain      The certificate chain.
     * @return The JWK encoded private key.
     */
    public static String get(PrivateKey privateKey, String alias, X509Certificate[] chain) {
        JwkExporter jwkExporter;

        if (privateKey instanceof RSAPrivateCrtKey) {
            jwkExporter = new RSAKeyExporter(privateKey);
        } else if (privateKey instanceof ECPrivateKey) {
            jwkExporter = new ECKeyExporter(privateKey);
        } else {
            jwkExporter = checkForJdkEdDSA(privateKey);

            if (jwkExporter == null) {
                // Don't bother to translate this exception. This condition will never be encountered
                // since DExportPrivateKeyType.isJwkSupported and JwkPublicKeyExporter.isPublicKeyTypeExportable
                // guard the UI to prevent calling this method for unsupported key types.
                throw new IllegalArgumentException("Not supported key type: " + privateKey.getClass().getName());
            }
        }

        return jwkExporter.export(alias, chain);
    }

    /**
     * JWK encode and encrypt a private key.
     *
     * @param privateKey    The private key
     * @param alias         The entry alias. Used for the JWK keyId. If null, then the JWK thumbprint is
     *                      used for the JWK keyId.
     * @param jweAlg        PBE JWE algorithm to use for encryption
     * @param password      Encryption password
     * @param compactFormat The JWE output format. True for compact encoding, false for JSON encoding
     * @return The encrypted encoding, JWE with JWK payload
     * @throws CryptoException Problem encountered while getting the encoded private key
     */
    public static String get(PrivateKey privateKey, String alias, JWEAlgorithm jweAlg, Password password,
            boolean compactFormat) throws CryptoException {

        return get(privateKey, alias, null, jweAlg, password, compactFormat);
    }

    /**
     * JWK encode a key pair with certificate.
     *
     * @param privateKey    The private key
     * @param alias         The entry alias. Used for the JWK keyId. If null, then the JWK thumbprint is
     *                      used for the JWK keyId.
     * @param chain         The certificate chain.
     * @param jweAlg        PBE JWE algorithm to use for encryption
     * @param password      Encryption password
     * @param compactFormat The JWE output format. True for compact encoding, false for JSON encoding
     * @return The encrypted encoding, JWE with JWK payload
     * @throws CryptoException Problem encountered while getting the encoded private key
     */
    public static String get(PrivateKey privateKey, String alias, X509Certificate[] chain, JWEAlgorithm jweAlg,
            Password password, boolean compactFormat) throws CryptoException {

        String jwePayload = get(privateKey, alias, chain);

        // Rather than exposing the JWE encryption method to the user, just pick it
        // based on the chosen PBES2 algorithm.
        EncryptionMethod enc;
        if (JWEAlgorithm.PBES2_HS256_A128KW.equals(jweAlg)) {
            enc = EncryptionMethod.A128GCM;
        } else if (JWEAlgorithm.PBES2_HS384_A192KW.equals(jweAlg)) {
            enc = EncryptionMethod.A192GCM;
        } else {
            enc = EncryptionMethod.A256GCM;
        }

        JWEHeader.Builder jweHeaderBuilder = new JWEHeader.Builder(jweAlg, enc)
                .contentType("jwk+json");

        PasswordBasedEncrypter encrypter = new PasswordBasedEncrypter(password.toByteArray(), PBES2_SALT_LENGTH,
                PBES2_ITERATION_COUNT);

        try {
            JWEObject jweObject = new JWEObject(jweHeaderBuilder.build(), new Payload(jwePayload));
            jweObject.encrypt(encrypter);
            if (compactFormat) {
                // compact
                return jweObject.serialize();
            } else {
                // JSON
                // JWEObjectJSON.encrypt does not apply any encrypter updates to the header
                return new JWEObjectJSON(jweObject).serializeGeneral();
            }
        } catch (JOSEException ex) {
            throw new CryptoException(res.getString("NoEncryptJwkPrivateKey.exception.message"), ex);
        }
    }

    /**
     * Load an encrypted JWK private key from the byte array.
     *
     * @param pvkData  BA to load the encrypted private key from
     * @param password Password to decrypt
     * @return The JWK encoded key
     * @throws PrivateKeyEncryptedException If private key is unencrypted
     * @throws CryptoException              Problem encountered while loading the key
     */
    public static JWK load(byte[] pvkData, Password password) throws CryptoException {

        // Check JWK is encrypted
        EncryptionType encType = getEncryptionType(pvkData);
        if (encType == null) {
            // Not a valid JWK key
            throw new CryptoException(res.getString("NotValidJwk.exception.message"));
        }

        if (encType == UNENCRYPTED) {
            throw new PrivateKeyUnencryptedException(res.getString("JwkIsUnencrypted.exception.message"));
        }

        JWEObjectJSON jweJson;
        String jweData = new String(pvkData);
        try {
            jweJson = JWEObjectJSON.parse(jweData);
        } catch (ParseException e) {
            try {
                JWEObject jweObject = JWEObject.parse(jweData);
                // convert to JWEObjectJSON so that two code paths are not needed for decrypting
                jweJson = new JWEObjectJSON(jweObject);
            }
            catch (ParseException ex) {
                throw new CryptoException(res.getString("NoLoadJwkPrivateKey.exception.message"), ex);
            }
        }

        try {
            PasswordBasedDecrypter decrypter = new PasswordBasedDecrypter(password.toByteArray());
            jweJson.decrypt(decrypter);
            return load(jweJson.getPayload().toBytes());
        } catch (JOSEException ex) {
            throw new CryptoException(res.getString("NoLoadJwkPrivateKey.exception.message"), ex);
        }
    }

    /**
     * Load an unencrypted JWK private or public key from the byte array.
     *
     * @param pvkData BA to load the unencrypted private key from
     * @return The private key
     * @throws PrivateKeyEncryptedException If private key is encrypted
     * @throws CryptoException              Problem encountered while loading the private key
     */
    public static JWK load(byte[] pvkData) throws CryptoException {
        // Check JWE is unencrypted
        EncryptionType encType = getEncryptionType(pvkData);

        if (encType == null) {
            // Not a valid JWK key
            throw new CryptoException(res.getString("NotValidJwk.exception.message"));
        }

        if (encType == ENCRYPTED) {
            throw new PrivateKeyEncryptedException(res.getString("JwkIsEncrypted.exception.message"));
        }

        try {
            return JWK.parse(new String(pvkData));
        } catch (ParseException ex) {
            throw new CryptoException(res.getString("NoLoadJwkPrivateKey.exception.message"), ex);
        }
    }

    /**
     * Converts a JWK encoded key to a private key.
     * @param jwkKey The JWK encoded key.
     * @return The private key.
     * @throws CryptoException If the JWK cannot be converted to a private key.
     */
    public static PrivateKey toPrivateKey(JWK jwkKey) throws CryptoException {
        PrivateKey privateKey;

        try {
            if (jwkKey.getKeyType().equals(KeyType.EC)) {
                privateKey = jwkKey.toECKey().toPrivateKey();
            } else if (jwkKey.getKeyType().equals(KeyType.OKP)) {
                // Nimbus+JOSE has not implemented OctetKeyPair.toPrivateKey(). Manually convert.
                OctetKeyPair okp = jwkKey.toOctetKeyPair();
                if (okp.getD() != null) {
                    Curve curve = okp.getCurve();
                    privateKey = KeyFactory.getInstance(KeyPairType.EDDSA.jce()).generatePrivate(
                            new EdECPrivateKeySpec(new NamedParameterSpec(curve.getStdName()), okp.getDecodedD()));
                    // KSE uses the BC interfaces for EdDSA keys so convert BC
                    privateKey = EccUtil.getEdPrivateKey(privateKey);
                } else {
                    privateKey = null;
                }
            } else if (jwkKey.getKeyType().equals(KeyType.RSA)) {
                privateKey = jwkKey.toRSAKey().toPrivateKey();
            } else {
                throw new CryptoException(MessageFormat.format(res.getString("UnsupportedJwkKeyType.exception.message"),
                        jwkKey.getKeyType()));
            }
        } catch (JOSEException | InvalidKeySpecException | NoSuchAlgorithmException ex) {
            throw new CryptoException(res.getString("NoLoadJwkPrivateKey.exception.message"), ex);
        }

        return privateKey;
    }

    /**
     * Converts a JWK encoded key to a public key.
     * @param jwkKey The JWK encoded key.
     * @return The public key.
     * @throws CryptoException If the JWK cannot be converted to a public key.
     */
    public static PublicKey toPublicKey(JWK jwkKey) throws CryptoException {
        PublicKey publicKey;

        try {
            if (jwkKey.getKeyType().equals(KeyType.EC)) {
                publicKey = jwkKey.toECKey().toPublicKey();
            } else if (jwkKey.getKeyType().equals(KeyType.OKP)) {
                return toPublicKey(jwkKey.toOctetKeyPair());
            } else if (jwkKey.getKeyType().equals(KeyType.RSA)) {
                publicKey = jwkKey.toRSAKey().toPublicKey();
            } else {
                throw new CryptoException(MessageFormat.format(res.getString("UnsupportedJwkKeyType.exception.message"),
                        jwkKey.getKeyType()));
            }
        } catch (JOSEException ex) {
            throw new CryptoException(res.getString("NoLoadJwkPrivateKey.exception.message"), ex);
        }

        return publicKey;
    }

    private static PublicKey toPublicKey(OctetKeyPair okp) throws CryptoException {
        // Nimbus+JOSE has not implemented OctetKeyPair.toPublicKey().
        // Manually convert using BC API.
        try {
            Curve crv = okp.getCurve();

            ASN1ObjectIdentifier curveIdentifier =
                    Curve.Ed25519.equals(crv) ? EdECObjectIdentifiers.id_Ed25519 :
                    Curve.Ed448.equals(crv)   ? EdECObjectIdentifiers.id_Ed448 :
                    null;

            if (curveIdentifier == null) {
                throw new IllegalArgumentException("Unsupported OKP curve: " + crv);
            }

            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(curveIdentifier),
                    okp.getDecodedX());
            return new JcaPEMKeyConverter().getPublicKey(spki);
        } catch (PEMException ex) {
            throw new CryptoException(res.getString("NoLoadJwkPrivateKey.exception.message"), ex);
        }
    }

    /**
     * Determines if the public key is exportable to JWK.
     *
     * @param publicKey The public key to export.
     * @return True if the public key can be exported to JWK.
     */
    public static boolean isPublicKeyTypeExportable(PublicKey publicKey) {
        try {
            switch (KeyPairUtil.getKeyPairType(publicKey)) {
            case ED448:
            case ED25519:
            case EDDSA:
            case RSA:
                return true;
            case EC:
            case ECDSA:
                KeyInfo keyInfo = KeyPairUtil.getKeyInfo(publicKey);
                String detailedAlgorithm = keyInfo.getDetailedAlgorithm();
                return ECKeyExporter.supportsCurve(detailedAlgorithm);
            default:
                return false;
            }
        } catch (Exception e) {
            throw JwkExporterException.notSupported(publicKey.getAlgorithm(), null);
        }
    }

    /**
     * Detect if a JWK private or public key is encrypted or not.
     *
     * @param jwkData BA containing JWK key in JSON format
     * @return Encryption type or null if not a valid JWK key
     */
    public static EncryptionType getEncryptionType(byte[] jwkData) {
        String jwkStr = new String(jwkData);

        try {
            JWEObject.parse(jwkStr);
            return ENCRYPTED;
        } catch (ParseException e) {
            // Data is not JWE compact form
        }

        try {
            JWEObjectJSON.parse(jwkStr);
            return ENCRYPTED;
        } catch (ParseException e) {
            // Data is not JWE JSON
        }

        try {
            JWK.parse(jwkStr);
            return UNENCRYPTED;
        } catch (ParseException e) {
            // Data is not JWK JSON
        }

        return null;
    }

    private static JwkExporter checkForJdkEdDSA(PrivateKey privateKey) {
        EdDSAPrivateKey edDSAPrivateKey = EccUtil.getEdPrivateKey(privateKey);
        if (edDSAPrivateKey != null) {
            return new EdDSAKeyExporter(edDSAPrivateKey);
        }
        return null;
    }

    private static JwkExporter checkForJdkEdDSA(PublicKey publicKey) {
        try {
            // Convert to BC EdDSAPublicKey instance by exporting/importing
            PublicKey pubKey = OpenSslPubUtil.load(OpenSslPubUtil.get(publicKey));
            if (pubKey instanceof EdDSAPublicKey) {
                return new EdDSAKeyExporter(pubKey);
            }
        } catch (CryptoException e) {
            // Ignore. It's not a valid EdDSA key so rely on the IllegalArgumentException
            // in the calling method.
        }
        return null;
    }

    private static class EdDSAKeyExporter implements JwkExporter {
        protected static final Map<String, Curve> SUPPORTED_CURVES =
                Map.of(
                        KeyPairType.ED25519.jce(), Curve.Ed25519,
                        KeyPairType.ED448.jce(),   Curve.Ed448
                );

        private final EdDSAPrivateKey privateKey;
        private final EdDSAPublicKey publicKey;

        private EdDSAKeyExporter(PrivateKey privateKey) {
            this.privateKey = (EdDSAPrivateKey) privateKey;
            this.publicKey = this.privateKey.getPublicKey();
        }

        private EdDSAKeyExporter(PublicKey publicKey) {
            this.privateKey = null;
            this.publicKey = (EdDSAPublicKey) publicKey;
        }

        private Curve getCurve(EdDSAKey bcEdDSAPublicKey) {
            return SUPPORTED_CURVES.get(bcEdDSAPublicKey.getAlgorithm());
        }

        @Override
        public String export(String alias, X509Certificate[] chain) {
            Curve curve = getCurve(publicKey);
            try {
                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                        publicKey.getEncoded());
                byte[] rawKey = subjectPublicKeyInfo.getPublicKeyData().getBytes();
                OctetKeyPair.Builder builder = new OctetKeyPair.Builder(curve, Base64URL.encode(rawKey));

                if (privateKey != null) {
                    ASN1Primitive privateKeyOctetString = ASN1Primitive.fromByteArray(
                            PrivateKeyInfo.getInstance(privateKey.getEncoded()).getPrivateKey().getOctets());
                    byte[] d = ASN1OctetString.getInstance(privateKeyOctetString.getEncoded()).getOctets();
                    builder.d(Base64URL.encode(d));
                }

                if (alias != null) {
                    builder.keyID(alias);
                } else {
                    builder.keyIDFromThumbprint();
                }

                if (chain != null && chain.length > 0) {
                    byte[] x5t = DigestUtil.getMessageDigest(chain[0].getEncoded(), DigestType.SHA1);
                    byte[] x5tS256 = DigestUtil.getMessageDigest(chain[0].getEncoded(), DigestType.SHA256);
                    builder.x509CertChain(encodeChain(chain))
                            .keyUse(KeyUse.from(chain[0]))
                            .notBeforeTime(chain[0].getNotBefore())
                            .expirationTime(chain[0].getNotAfter())
                            .x509CertThumbprint(Base64URL.encode(x5t))
                            .x509CertSHA256Thumbprint(Base64URL.encode(x5tS256));
                }

                return builder.build().toJSONString();
            } catch (Exception e) {
                throw JwkExporterException.keyExportFailed(alias, e);
            }
        }
    }

    public static class ECKeyExporter implements JwkExporter {
        private static final Map<String, Curve> SUPPORTED_CURVES =
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

        private final ECPrivateKey privateKey;
        private final ECPublicKey publicKey;

        private ECKeyExporter(PrivateKey privateKey) {
            this.privateKey = (ECPrivateKey) privateKey;
            this.publicKey = constructPublicKey(this.privateKey);
        }

        private ECKeyExporter(PublicKey publicKey) {
            this.privateKey = null;
            this.publicKey = (ECPublicKey) publicKey;
        }

        /**
         * Determines the EC curve is supported by JWK.
         *
         * @param curveName The EC curve name.
         * @return True if the curve is supported. False if not supported.
         */
        public static boolean supportsCurve(String curveName) {
            return SUPPORTED_CURVES.containsKey(curveName);
        }

        private Curve getCurve(ECPrivateKey privateKey) {
            try {
                String curveName = KeyPairUtil.getKeyInfo(privateKey).getDetailedAlgorithm();
                return SUPPORTED_CURVES.get(curveName);
            } catch (CryptoException e) {
                throw JwkExporterException.notSupported(privateKey.getAlgorithm(), e);
            }
        }

        private Curve getCurve(ECPublicKey publicKey) {
            try {
                String curveName = KeyPairUtil.getKeyInfo(publicKey).getDetailedAlgorithm();
                return SUPPORTED_CURVES.get(curveName);
            } catch (CryptoException e) {
                throw JwkExporterException.notSupported(publicKey.getAlgorithm(), e);
            }
        }

        @Override
        public String export(String alias, X509Certificate[] chain) {
            Curve curve = getCurve(publicKey);
            try {
                ECKey.Builder builder = new ECKey.Builder(curve, publicKey);

                if (privateKey != null) {
                    builder.privateKey(privateKey);
                }

                if (alias != null) {
                    builder.keyID(alias);
                } else {
                    builder.keyIDFromThumbprint();
                }

                if (chain != null && chain.length > 0) {
                    byte[] x5t = DigestUtil.getMessageDigest(chain[0].getEncoded(), DigestType.SHA1);
                    byte[] x5tS256 = DigestUtil.getMessageDigest(chain[0].getEncoded(), DigestType.SHA256);
                    builder.x509CertChain(encodeChain(chain))
                            .keyUse(KeyUse.from(chain[0]))
                            .notBeforeTime(chain[0].getNotBefore())
                            .expirationTime(chain[0].getNotAfter())
                            .x509CertThumbprint(Base64URL.encode(x5t))
                            .x509CertSHA256Thumbprint(Base64URL.encode(x5tS256));
                }

                return builder.build().toJSONString();
            } catch (Exception e) {
                throw JwkExporterException.keyExportFailed(alias, e);
            }
        }

        private ECPublicKey constructPublicKey(ECPrivateKey privateKey) {
            try {
                // Don't use BC provider. It generates explicitly specified curves rather than named curves.
                KeyFactory keyFactory = KeyFactory.getInstance("EC");

                Curve crv = getCurve(privateKey);

                ECParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec(EccUtil.getNamedCurve(privateKey));
                org.bouncycastle.math.ec.ECPoint Q = bcSpec.getG().multiply(privateKey.getS());
                org.bouncycastle.math.ec.ECPoint bcW = bcSpec.getCurve().decodePoint(Q.getEncoded(false));
                ECPoint ecPoint = new ECPoint(bcW.getAffineXCoord().toBigInteger(), bcW.getAffineYCoord().toBigInteger());
                return (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(ecPoint, crv.toECParameterSpec()));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                // Ignore. The logic is correct for valid private keys and this method shouldn't be
                // seeing invalid keys.
            }
            return null;
        }
    }

    private static class RSAKeyExporter implements JwkExporter {
        private final RSAPrivateCrtKey privateKey;
        private final RSAPublicKey publicKey;

        private RSAKeyExporter(PrivateKey privateKey) {
            this.privateKey = (RSAPrivateCrtKey) privateKey;
            this.publicKey = constructPublicKey(this.privateKey);
        }

        private RSAKeyExporter(PublicKey publicKey) {
            this.privateKey = null;
            this.publicKey = (RSAPublicKey) publicKey;
        }

        @Override
        public String export(String alias, X509Certificate[] chain) {
            try {
                RSAKey.Builder builder = new RSAKey.Builder(publicKey);

                if (privateKey != null) {
                    builder.privateKey(privateKey);
                }

                if (alias != null) {
                    builder.keyID(alias);
                } else {
                    builder.keyIDFromThumbprint();
                }

                if (chain != null && chain.length > 0) {
                    byte[] x5t = DigestUtil.getMessageDigest(chain[0].getEncoded(), DigestType.SHA1);
                    byte[] x5tS256 = DigestUtil.getMessageDigest(chain[0].getEncoded(), DigestType.SHA256);
                    builder.x509CertChain(encodeChain(chain))
                            .keyUse(KeyUse.from(chain[0]))
                            .notBeforeTime(chain[0].getNotBefore())
                            .expirationTime(chain[0].getNotAfter())
                            .x509CertThumbprint(Base64URL.encode(x5t))
                            .x509CertSHA256Thumbprint(Base64URL.encode(x5tS256));
                }

                return builder.build().toJSONString();
            } catch (Exception e) {
                throw JwkExporterException.keyExportFailed(alias, e);
            }
        }

        private RSAPublicKey constructPublicKey(RSAPrivateCrtKey privateKey) {
            try {
                return (RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                // Ignore. The logic is correct for valid private keys and this method shouldn't be
                // seeing invalid keys.
            }
            return null;
        }
    }

    private static List<Base64> encodeChain(X509Certificate[] chain) throws CertificateEncodingException {
        List<Base64> x5c = new ArrayList<>();
        for (X509Certificate c : chain) {
            x5c.add(Base64.encode(c.getEncoded()));
        }
        return x5c;
    }
}
