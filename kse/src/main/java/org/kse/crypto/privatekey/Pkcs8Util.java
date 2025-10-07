/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

import static org.kse.crypto.keypair.KeyPairType.DSA;
import static org.kse.crypto.keypair.KeyPairType.RSA;
import static org.kse.crypto.privatekey.EncryptionType.ENCRYPTED;
import static org.kse.crypto.privatekey.EncryptionType.UNENCRYPTED;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

/**
 * Provides utility methods relating to PKCS #8 encoded private keys.
 */
public class Pkcs8Util {
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/privatekey/resources");
    private static final String PKCS8_UNENC_PVK_PEM_TYPE = "PRIVATE KEY";
    private static final String PKCS8_ENC_PVK_PEM_TYPE = "ENCRYPTED PRIVATE KEY";

    private Pkcs8Util() {
    }

    /**
     * PKCS #8 encode a private key.
     *
     * @param privateKey The private key
     * @return The encoding
     */
    public static byte[] get(PrivateKey privateKey) {
        return privateKey.getEncoded();
    }

    /**
     * PKCS #8 encode a private key and PEM the encoding.
     *
     * @param privateKey The private key
     * @return The PEM'd encoding
     */
    public static String getPem(PrivateKey privateKey) {
        PemInfo pemInfo = new PemInfo(PKCS8_UNENC_PVK_PEM_TYPE, null, privateKey.getEncoded());
        return PemUtil.encode(pemInfo);
    }

    /**
     * PKCS #8 encode and encrypt a private key.
     *
     * @param privateKey The private key
     * @param pbeType    PBE algorithm to use for encryption
     * @param password   Encryption password
     * @return The encrypted encoding
     * @throws CryptoException Problem encountered while getting the encoded private key
     * @throws IOException     If an I/O error occurred
     */
    public static byte[] getEncrypted(PrivateKey privateKey, Pkcs8PbeType pbeType, Password password)
            throws CryptoException, IOException {
        try {
            JcePKCSPBEOutputEncryptorBuilder encryptorBuilder = new JcePKCSPBEOutputEncryptorBuilder(pbeType.oid());
            encryptorBuilder.setProvider(KSE.BC);
            if (pbeType.prf() != null) {
                encryptorBuilder.setPRF(pbeType.prf());
            }
            OutputEncryptor encryptor = encryptorBuilder.build(password.toCharArray());

            PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo =
                    new PKCS8EncryptedPrivateKeyInfoBuilder(get(privateKey)).build(encryptor);

            return encryptedPrivateKeyInfo.getEncoded();
        } catch (OperatorCreationException ex) {
            throw new CryptoException("NoEncryptPkcs8PrivateKey.exception.message", ex);
        }
    }

    /**
     * PKCS #8 encode and encrypt a private key and PEM the encoding.
     *
     * @param privateKey The private key
     * @param pbeType    PBE algorithm to use for encryption
     * @param password   Encryption password
     * @return The encrypted, PEM'd encoding
     * @throws CryptoException Problem encountered while getting the encoded private key
     * @throws IOException     If an I/O error occurred
     */
    public static String getEncryptedPem(PrivateKey privateKey, Pkcs8PbeType pbeType, Password password)
            throws CryptoException, IOException {
        PemInfo pemInfo = new PemInfo(PKCS8_ENC_PVK_PEM_TYPE, null, getEncrypted(privateKey, pbeType, password));

        return PemUtil.encode(pemInfo);
    }

    /**
     * Load an unencrypted PKCS #8 private key from the stream. The encoding of
     * the private key may be PEM or DER.
     *
     * @param pvkData BA to load the unencrypted private key from
     * @return The private key
     * @throws PrivateKeyEncryptedException If private key is encrypted
     * @throws CryptoException              Problem encountered while loading the private key
     * @throws IOException                  If an I/O error occurred
     */
    public static PrivateKey load(byte[] pvkData) throws CryptoException, IOException {

        // Check pkcs #8 is unencrypted
        EncryptionType encType = getEncryptionType(pvkData);

        if (encType == null) {
            // Not a valid PKCS #8 private key
            throw new CryptoException(res.getString("NotValidPkcs8.exception.message"));
        }

        if (encType == ENCRYPTED) {
            throw new PrivateKeyEncryptedException(res.getString("Pkcs8IsEncrypted.exception.message"));
        }

        byte[] pvkBytes = null;
        // Check if stream is PEM encoded
        PemInfo pemInfo = PemUtil.decode(pvkData);

        if (pemInfo != null) {
            // It is - get DER from PEM
            pvkBytes = pemInfo.getContent();
        }

        /*
         * If we haven't got the key bytes via PEM then just use stream
         * contents directly (assume it is DER encoded)
         */
        if (pvkBytes == null) {
            // Read in private key bytes
            pvkBytes = pvkData;
        }

        try {
            // Determine private key algorithm from key bytes
            String privateKeyAlgorithm = getPrivateKeyAlgorithm(pvkBytes);

            // Convert bytes to private key
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pvkBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(privateKeyAlgorithm);

            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoException(res.getString("NoLoadPkcs8PrivateKey.exception.message"), ex);
        }
    }

    /**
     * Load an encrypted PKCS #8 private key from the specified stream. The
     * encoding of the private key may be PEM or DER.
     *
     * @param pvkData  Stream load the encrypted private key from
     * @param password Password to decrypt
     * @return The private key
     * @throws PrivateKeyUnencryptedException     If private key is unencrypted
     * @throws PrivateKeyPbeNotSupportedException If private key PBE algorithm is not supported
     * @throws CryptoException                    Problem encountered while loading the private key
     * @throws IOException                        If an I/O error occurred
     */
    public static PrivateKey loadEncrypted(byte[] pvkData, Password password) throws CryptoException, IOException {

        // Check PKCS#8 is encrypted
        EncryptionType encType = getEncryptionType(pvkData);
        if (encType == null) {
            // Not a valid PKCS #8 private key
            throw new CryptoException(res.getString("NotValidPkcs8.exception.message"));
        }
        if (encType == UNENCRYPTED) {
            throw new PrivateKeyUnencryptedException(res.getString("Pkcs8IsEncrypted.exception.message"));
        }

        // Check if stream is PEM encoded
        PemInfo pemInfo = PemUtil.decode(pvkData);
        byte[] encPvk = null;
        if (pemInfo != null) {
            // It is - get DER from PEM
            encPvk = pemInfo.getContent();
        }

        // If we haven't got the encrypted bytes via PEM then assume it is DER encoded
        if (encPvk == null) {
            encPvk = pvkData;
        }

        // try to read PKCS#8 info
        PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
        try {
            encryptedPrivateKeyInfo = new PKCS8EncryptedPrivateKeyInfo(
                    org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo.getInstance(encPvk));
        } catch (Exception e) {
            // Not a valid PKCS #8 private key
            throw new CryptoException(res.getString("NotValidPkcs8.exception.message"));
        }

        // decrypt and create PrivateKey object from ASN.1 structure
        try {
            InputDecryptorProvider decProv = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(KSE.BC)
                                                                                          .build(password.toCharArray());
            PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decProv);

            return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
        } catch (Exception ex) {
            throw new CryptoException(res.getString("NoLoadPkcs8PrivateKey.exception.message"), ex);
        }
    }

    /**
     * Detect if a PKCS #8 private key is encrypted or not.
     *
     * @param pkcs8 BA containing PKCS #8 private key in PEM or DER format
     * @return Encryption type or null if not a valid PKCS #8 private key
     * @throws IOException If an I/O problem occurred
     */
    public static EncryptionType getEncryptionType(byte[] pkcs8) throws IOException {

        if (PemUtil.isPemFormat(pkcs8)) {
            PemInfo pemInfo = PemUtil.decode(pkcs8);

            // PEM encoded?
            if (pemInfo != null) {
                String pemType = pemInfo.getType();

                // Encrypted in pem format?
                if (pemType.equals(Pkcs8Util.PKCS8_ENC_PVK_PEM_TYPE)) {
                    return ENCRYPTED;
                }
                // Unencrypted in pem format?
                else if (pemType.equals(Pkcs8Util.PKCS8_UNENC_PVK_PEM_TYPE)) {
                    return UNENCRYPTED;
                }
            }
        }

        // DER format?
        try {
            // Read in as ASN.1 and check structure against the following
            ASN1Primitive key = ASN1Primitive.fromByteArray(pkcs8);

            if (key instanceof ASN1Sequence) {
                ASN1Sequence sequence = (ASN1Sequence) key;

                // May be unencrypted
                if ((sequence.size() == 3) || (sequence.size() == 4)) {
                    // @formatter:off

                    /*
                     * Unencrypted PKCS #8 Private Key:
                     *
                     * PrivateKeyInfo ::= OneAsymmetricKey

                     * OneAsymmetricKey ::= ASN1Sequence {
                     *      version Version,
                     *      privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
                     *      privateKey PrivateKey,
                     *      attributes [0] IMPLICIT Attributes OPTIONAL
                     *      publicKey  [1] BIT STRING OPTIONAL
                     * }
                     *
                     * Version ::= ASN1Integer
                     * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
                     * PrivateKey ::= OCTET STRING
                     * Attributes ::= SET OF Attribute
                     */

                    // @formatter:on

                    Object obj1 = sequence.getObjectAt(0);
                    Object obj2 = sequence.getObjectAt(1);
                    Object obj3 = sequence.getObjectAt(2);

                    if (!(obj1 instanceof ASN1Integer)) {
                        return null;
                    }

                    ASN1Integer version = (ASN1Integer) obj1;

                    if (!version.getValue().equals(BigInteger.ZERO)) {
                        return null;
                    }

                    if (!(obj2 instanceof ASN1Sequence)) {
                        return null;
                    }

                    if (!sequenceIsAlgorithmIdentifier((ASN1Sequence) obj2)) {
                        return null;
                    }

                    if (!(obj3 instanceof ASN1OctetString)) {
                        return null;
                    }

                    return UNENCRYPTED;
                } else if (sequence.size() == 2) {
                    // @formatter:off

                    /*
                     * Encrypted PKCS #8 Private Key:
                     *
                     * EncryptedPrivateKeyInfo ::= ASN1Sequence {
                     *      encryptionAlgorithm EncryptionAlgorithmIdentifier,
                     *      encryptedData EncryptedData
                     * }
                     *
                     * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
                     * EncryptedData ::= OCTET STRING
                     */

                    // @formatter:on

                    // May be encrypted
                    Object obj1 = sequence.getObjectAt(0);
                    Object obj2 = sequence.getObjectAt(1);

                    if (!(obj1 instanceof ASN1Sequence)) {
                        return null;
                    }

                    if (!sequenceIsAlgorithmIdentifier((ASN1Sequence) obj1)) {
                        return null;
                    }

                    if (!(obj2 instanceof ASN1OctetString)) {
                        return null;
                    }

                    return ENCRYPTED;
                }
            }
        } catch (Exception ex) {
            // Structure not as expected for PKCS #8
            return null;
        }

        return null;
    }

    private static boolean sequenceIsAlgorithmIdentifier(ASN1Sequence sequence) {
        // @formatter:off
        /*
         * AlgorithmIdentifier ::= ASN1Sequence {
         *      algorithm OBJECT IDENTIFIER,
         *      parameters ANY DEFINED BY algorithm OPTIONAL
         * }
         */
        // @formatter:on

        if ((sequence.size() != 1) && (sequence.size() != 2)) {
            return false;
        }

        Object obj1 = sequence.getObjectAt(0);

        return obj1 instanceof ASN1ObjectIdentifier;

    }

    private static String getPrivateKeyAlgorithm(byte[] unencPkcs8) throws IOException, CryptoException {
        // @formatter:off
        /*
         * Get private key algorithm from unencrypted PKCS #8 bytes:
         *
         * PrivateKeyInfo ::= ASN1Sequence {
         *      version Version,
         *      privateKeyAlgorithm PrivateKeyAlgorithmIdentifier, privateKey
         *      PrivateKey, attributes [0] IMPLICIT Attributes OPTIONAL
         * }
         *
         * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
         *
         * AlgorithmIdentifier ::= ASN1Sequence {
         *      algorithm OBJECT IDENTIFIER,
         *      parameters ANY DEFINED BY algorithm OPTIONAL
         * }
         */
        // @formatter:on

        try (ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(unencPkcs8))) {

            ASN1Encodable derEnc;
            try {
                derEnc = ais.readObject();
            } catch (OutOfMemoryError err) { // Happens with some non ASN.1 files
                throw new CryptoException(res.getString("NoUnencryptedPkcs8.exception.message"));
            }

            if (!(derEnc instanceof ASN1Sequence)) {
                throw new CryptoException(res.getString("NoUnencryptedPkcs8.exception.message"));
            }

            ASN1Sequence privateKeyInfoSequence = (ASN1Sequence) derEnc;

            derEnc = privateKeyInfoSequence.getObjectAt(1);

            if (!(derEnc instanceof ASN1Sequence)) {
                throw new CryptoException(res.getString("NoUnencryptedPkcs8.exception.message"));
            }

            ASN1Sequence privateKeyAlgorithmSequence = (ASN1Sequence) derEnc;

            derEnc = privateKeyAlgorithmSequence.getObjectAt(0);

            if (!(derEnc instanceof ASN1ObjectIdentifier)) {
                throw new CryptoException(res.getString("NoUnencryptedPkcs8.exception.message"));
            }

            ASN1ObjectIdentifier algorithmOid = (ASN1ObjectIdentifier) derEnc;

            String oid = algorithmOid.getId();

            if (oid.equals(RSA.oid())) {
                return RSA.jce();
            } else if (oid.equals(DSA.oid())) {
                return DSA.jce();
            } else {
                // TODO support other algorithms
                return oid; // Unknown algorithm
            }
        }
    }
}
