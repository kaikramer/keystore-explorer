/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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
package org.kse.crypto.signing;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_RSASSA_PSS;
import static org.kse.crypto.digest.DigestType.MD5;
import static org.kse.crypto.digest.DigestType.RIPEMD160;
import static org.kse.crypto.digest.DigestType.SHA1;
import static org.kse.crypto.digest.DigestType.SHA224;
import static org.kse.crypto.digest.DigestType.SHA256;
import static org.kse.crypto.digest.DigestType.SHA384;
import static org.kse.crypto.digest.DigestType.SHA3_224;
import static org.kse.crypto.digest.DigestType.SHA3_256;
import static org.kse.crypto.digest.DigestType.SHA3_384;
import static org.kse.crypto.digest.DigestType.SHA3_512;
import static org.kse.crypto.digest.DigestType.SHA512;
import static org.kse.crypto.digest.DigestType.SHAKE256;

import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.ecc.EdDSACurves;

/**
 * Enumeration of Signature Types supported by the X509CertUtil class.
 */
public enum SignatureType {

    // @formatter:off

	// DSA
	SHA1_DSA("SHA1withDSA", "1.2.840.10040.4.3", SHA1, "SignatureType.Sha1WithDsa"),
	SHA224_DSA("SHA224withDSA", "2.16.840.1.101.3.4.3.1", SHA224, "SignatureType.Sha224WithDsa"),
	SHA256_DSA("SHA256withDSA", "2.16.840.1.101.3.4.3.2", SHA256, "SignatureType.Sha256WithDsa"),
	SHA384_DSA("SHA384withDSA", "2.16.840.1.101.3.4.3.3", SHA384, "SignatureType.Sha384WithDsa"),
	SHA512_DSA("SHA512withDSA", "2.16.840.1.101.3.4.3.4", SHA512, "SignatureType.Sha512WithDsa"),

	// RSA
	MD5_RSA("MD5withRSA", "1.2.840.113549.1.1.4", MD5, "SignatureType.Md5WithRsa"),
	RIPEMD160_RSA("RIPEMD160withRSA", "1.3.36.3.3.1.2", RIPEMD160, "SignatureType.Ripemd160WithRsa"),
	SHA1_RSA("SHA1withRSA", "1.2.840.113549.1.1.5", SHA1, "SignatureType.Sha1WithRsa"),
	SHA224_RSA("SHA224withRSA", "1.2.840.113549.1.1.14", SHA224, "SignatureType.Sha224WithRsa"),
	SHA256_RSA("SHA256withRSA", "1.2.840.113549.1.1.11", SHA256, "SignatureType.Sha256WithRsa"),
	SHA384_RSA("SHA384withRSA", "1.2.840.113549.1.1.12", SHA384, "SignatureType.Sha384WithRsa"),
	SHA512_RSA("SHA512withRSA", "1.2.840.113549.1.1.13", SHA512, "SignatureType.Sha512WithRsa"),

	// RSASSA-PSS (there is only one OID for the PSS signature scheme, the parameters define the exact algorithm)
	SHA1WITHRSAANDMGF1("SHA1WITHRSAANDMGF1", id_RSASSA_PSS.getId(), SHA1, "SignatureType.Sha1WithRsaAndMGF1"),
	SHA224WITHRSAANDMGF1("SHA224WITHRSAANDMGF1", id_RSASSA_PSS.getId(), SHA224, "SignatureType.Sha224WithRsaAndMGF1"),
	SHA256WITHRSAANDMGF1("SHA256WITHRSAANDMGF1", id_RSASSA_PSS.getId(), SHA256, "SignatureType.Sha256WithRsaAndMGF1"),
	SHA384WITHRSAANDMGF1("SHA384WITHRSAANDMGF1", id_RSASSA_PSS.getId(), SHA384, "SignatureType.Sha384WithRsaAndMGF1"),
	SHA512WITHRSAANDMGF1("SHA512WITHRSAANDMGF1", id_RSASSA_PSS.getId(), SHA512, "SignatureType.Sha512WithRsaAndMGF1"),

	// RSA with SHA3 and MGF1
	SHA3_224WITHRSAANDMGF1("SHA3-224WITHRSAANDMGF1", id_RSASSA_PSS.getId(), SHA3_224, "SignatureType.Sha3_224WithRsaAndMGF1"),
	SHA3_256WITHRSAANDMGF1("SHA3-256WITHRSAANDMGF1", id_RSASSA_PSS.getId(), SHA3_256, "SignatureType.Sha3_256WithRsaAndMGF1"),
	SHA3_384WITHRSAANDMGF1("SHA3-384WITHRSAANDMGF1", id_RSASSA_PSS.getId(), SHA3_384, "SignatureType.Sha3_384WithRsaAndMGF1"),
	SHA3_512WITHRSAANDMGF1("SHA3-512WITHRSAANDMGF1", id_RSASSA_PSS.getId(), SHA3_512, "SignatureType.Sha3_512WithRsaAndMGF1"),

	// ECDSA
	SHA1_ECDSA("SHA1withECDSA", "1.2.840.10045.4.1", SHA1, "SignatureType.Sha1WithEcDsa"),
	SHA224_ECDSA("SHA224withECDSA", "1.2.840.10045.4.3.1", SHA224, "SignatureType.Sha224WithEcDsa"),
	SHA256_ECDSA("SHA256withECDSA", "1.2.840.10045.4.3.2", SHA256, "SignatureType.Sha256WithEcDsa"),
	SHA384_ECDSA("SHA384withECDSA", "1.2.840.10045.4.3.3", SHA384, "SignatureType.Sha384WithEcDsa"),
	SHA512_ECDSA("SHA512withECDSA", "1.2.840.10045.4.3.4", SHA512, "SignatureType.Sha512WithEcDsa"),

	// EdDSA
	ED25519("Ed25519", EdDSACurves.ED25519.oid().getId(), SHA512, "SignatureType.Ed25519"),
	ED448("Ed448", EdDSACurves.ED448.oid().getId(), SHAKE256, "SignatureType.Ed448");
	// @formatter:on

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/signing/resources");
    private static final String RSASSA_PSS_OID = id_RSASSA_PSS.getId();
    private String jce;
    private String oid;
    private DigestType digestType;
    private String friendlyKey;

    SignatureType(String jce, String oid, DigestType digestType, String friendlyKey) {
        this.jce = jce;
        this.oid = oid;
        this.digestType = digestType;
        this.friendlyKey = friendlyKey;
    }

    /**
     * Get signature type JCE name.
     *
     * @return JCE name
     */
    public String jce() {
        return jce;
    }

    /**
     * Get signature type Object Identifier.
     *
     * @return Object Identifier
     */
    public String oid() {
        return oid;
    }

    /**
     * Get signature type's digest type.
     *
     * @return Digest type
     */
    public DigestType digestType() {
        return digestType;
    }

    /**
     * Get type's friendly name.
     *
     * @return Friendly name
     */
    public String friendly() {
        return res.getString(friendlyKey);
    }

    /**
     * Get the signature types compatible with DSA.
     *
     * @return DSA signature types
     */
    public static List<SignatureType> dsaSignatureTypes() {
        List<SignatureType> signatureTypes = new ArrayList<>();

        signatureTypes.add(SHA1_DSA);
        signatureTypes.add(SHA224_DSA);
        signatureTypes.add(SHA256_DSA);
        signatureTypes.add(SHA384_DSA);
        signatureTypes.add(SHA512_DSA);

        return signatureTypes;
    }

    /**
     * Get the signature types compatible with ECDSA.
     *
     * @return ECDSA signature types
     */
    public static List<SignatureType> ecdsaSignatureTypes() {
        List<SignatureType> signatureTypes = new ArrayList<>();

        signatureTypes.add(SHA1_ECDSA);
        //signatureTypes.add(SHA224_ECDSA); // not supported by Sun provider
        signatureTypes.add(SHA256_ECDSA);
        signatureTypes.add(SHA384_ECDSA);
        signatureTypes.add(SHA512_ECDSA);

        signatureTypes.add(ED25519);
        signatureTypes.add(ED448);

        return signatureTypes;
    }

    /**
     * Get the signature types compatible with RSA.
     *
     * @return RSA signature types
     */
    public static List<SignatureType> rsaSignatureTypes() {
        List<SignatureType> signatureTypes = new ArrayList<>();

        signatureTypes.add(RIPEMD160_RSA);
        signatureTypes.add(SHA1_RSA);
        signatureTypes.add(SHA224_RSA);
        signatureTypes.add(SHA256_RSA);
        signatureTypes.add(SHA384_RSA);
        signatureTypes.add(SHA512_RSA);
        signatureTypes.add(SHA1WITHRSAANDMGF1);
        signatureTypes.add(SHA224WITHRSAANDMGF1);
        signatureTypes.add(SHA256WITHRSAANDMGF1);
        signatureTypes.add(SHA384WITHRSAANDMGF1);
        signatureTypes.add(SHA512WITHRSAANDMGF1);

        // SHA3 signatures cause problems when reading certificates with standard providers (e.g. in P12 keystore)
        // because at least up to Java 15 there is no support for SHA3 signatures (see http://openjdk.java.net/jeps/287)
        //signatureTypes.add(SHA3_224WITHRSAANDMGF1);
        //signatureTypes.add(SHA3_256WITHRSAANDMGF1);
        //signatureTypes.add(SHA3_384WITHRSAANDMGF1);
        //signatureTypes.add(SHA3_512WITHRSAANDMGF1);

        return signatureTypes;
    }

    /**
     * Get the signature types compatible with RSA at the supplied key size.
     *
     * @param keySize Key size in bits
     * @return RSA signature types
     */
    public static List<SignatureType> rsaSignatureTypes(int keySize) {
        List<SignatureType> signatureTypes = rsaSignatureTypes();

        // SHA-512 requires RSA key length 512 + 233 bits padding, round up to nearest power of 8
        if (keySize < 752) {
            signatureTypes.remove(SHA512_RSA);
        }

        // SHA-384 requires RSA key length 384 + 233 bits padding, round up to nearest power of 8
        if (keySize < 624) {
            signatureTypes.remove(SHA384_RSA);
        }

        return signatureTypes;
    }

    /**
     * Resolve the supplied JCE name to a matching Signature type.
     *
     * @param jce JCE name
     * @return Signature type or null if none
     */
    public static SignatureType resolveJce(String jce) {
        for (SignatureType signatureType : values()) {
            if (jce.equals(signatureType.jce())) {
                return signatureType;
            }
        }

        return null;
    }

    /**
     * Resolve the supplied object identifier to a matching Signature type.
     *
     * @param oid          Object identifier
     * @param sigAlgParams Optional signature algorithm parameters (can be null)
     * @return Signature type or null if none
     */
    public static SignatureType resolveOid(String oid, byte[] sigAlgParams) {

        DigestType hashAlg = detectHashAlg(sigAlgParams);

        for (SignatureType signatureType : values()) {

            // PSS has one OID for all variations, so we have to compare hash algorithm as well
            if (RSASSA_PSS_OID.equals(oid)) {
                if (signatureType.oid().equals(oid) && signatureType.digestType == hashAlg) {
                    return signatureType;
                }
            } else if (signatureType.oid().equals(oid)) {
                return signatureType;
            }
        }

        return null;
    }

    private static DigestType detectHashAlg(byte[] sigAlgParams) {
        if (sigAlgParams == null) {
            return null;
        }
        try {
            RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(sigAlgParams);
            return DigestType.resolveOid(pssParams.getHashAlgorithm().getAlgorithm().getId());
        } catch (Exception e) {
            return DigestType.SHA1; // default for PSS
        }
    }

    /**
     * Returns friendly name.
     *
     * @return Friendly name
     */
    @Override
    public String toString() {
        return friendly();
    }
}
