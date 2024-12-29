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
package org.kse.crypto.keypair;

import static org.kse.crypto.KeyType.ASYMMETRIC;
import static org.kse.crypto.ecc.EdDSACurves.ED25519;
import static org.kse.crypto.ecc.EdDSACurves.ED448;
import static org.kse.crypto.keypair.KeyPairType.DSA;
import static org.kse.crypto.keypair.KeyPairType.EC;
import static org.kse.crypto.keypair.KeyPairType.ECDSA;
import static org.kse.crypto.keypair.KeyPairType.EDDSA;
import static org.kse.crypto.keypair.KeyPairType.RSA;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.ecc.EdDSACurves;

/**
 * Provides utility methods relating to asymmetric key pairs.
 */
public final class KeyPairUtil {
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/keypair/resources");

    private KeyPairUtil() {
    }

    /**
     * Generate a key pair.
     *
     * @param keyPairType Key pair type to generate
     * @param keySize     Key size of key pair
     * @param provider    Crypto provider used for key generation
     * @return A keypair
     * @throws CryptoException If there was a problem generating the key pair
     */
    public static KeyPair generateKeyPair(KeyPairType keyPairType, int keySize, Provider provider)
            throws CryptoException {
        try {
            // Get a key pair generator
            KeyPairGenerator keyPairGen = null;

            if (provider != null) {
                keyPairGen = KeyPairGenerator.getInstance(keyPairType.jce(), provider);
            } else {
                // Always use BC provider for RSA
                if (keyPairType == RSA) {
                    keyPairGen = KeyPairGenerator.getInstance(keyPairType.jce(), KSE.BC);
                } else {
                    // Use default provider for DSA
                    keyPairGen = KeyPairGenerator.getInstance(keyPairType.jce());
                }
            }

            // Create a SecureRandom
            SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");

            // Initialise key pair generator with key strength and randomness
            keyPairGen.initialize(keySize, rand);

            // Generate and return the key pair
            return keyPairGen.generateKeyPair();
        } catch (GeneralSecurityException ex) {
            throw new CryptoException(
                    MessageFormat.format(res.getString("NoGenerateKeypair.exception.message"), keyPairType), ex);
        }
    }

    /**
     * Generate an EC key pair.
     *
     * @param curveName Name of the ECC curve
     * @param provider  A JCE provider.
     * @return A key pair
     * @throws CryptoException If there was a problem generating the key pair
     */
    public static KeyPair generateECKeyPair(String curveName, Provider provider) throws CryptoException {
        try {
            // Get a key pair generator
            KeyPairGenerator keyPairGen;

            if (EdDSACurves.ED25519.jce().equals(curveName) || EdDSACurves.ED448.jce().equals(curveName)) {
                keyPairGen = KeyPairGenerator.getInstance(curveName, KSE.BC);
            } else if (provider != null) {
                keyPairGen = KeyPairGenerator.getInstance(KeyPairType.EC.jce(), provider);
                keyPairGen.initialize(new ECGenParameterSpec(curveName), SecureRandom.getInstance("SHA1PRNG"));
            } else {
                keyPairGen = KeyPairGenerator.getInstance(KeyPairType.EC.jce(), KSE.BC);
                keyPairGen.initialize(new ECGenParameterSpec(curveName), SecureRandom.getInstance("SHA1PRNG"));
            }

            // Generate and return the key pair
            return keyPairGen.generateKeyPair();

        } catch (GeneralSecurityException ex) {
            throw new CryptoException(
                    MessageFormat.format(res.getString("NoGenerateKeypair.exception.message"), KeyPairType.EC), ex);
        }
    }

    /**
     * Checks if the passed provider is an instance of "sun.security.mscapi.SunMSCAPI".
     *
     * @param provider A JCE provider.
     * @return True, if instance of SunMSCAPI
     */
    public static boolean isSunMSCAPI(Provider provider) {

        Class<?> sunMSCAPI = null;
        try {
            sunMSCAPI = Class.forName("sun.security.mscapi.SunMSCAPI");
        } catch (Exception e) {
            return false;
        }

        if (sunMSCAPI == null) {
            return false;
        }

        return sunMSCAPI.isInstance(provider);
    }

    /**
     * Checks if the passed provider is an instance of "sun.security.mscapi.SunMSCAPI".
     *
     * @param provider A JCE provider.
     * @return True, if instance of SunMSCAPI
     */
    public static boolean isSunJCE(Provider provider) {

        Class<?> sunJCE = null;
        try {
            sunJCE = Class.forName("com.sun.crypto.provider.SunJCE");
        } catch (Exception e) {
            return false;
        }

        if (sunJCE == null) {
            return false;
        }

        return sunJCE.isInstance(provider);
    }

    /**
     * Get the information about the supplied public key.
     *
     * @param publicKey The public key
     * @return Key information
     * @throws CryptoException If there is a problem getting the information
     */
    public static KeyInfo getKeyInfo(PublicKey publicKey) throws CryptoException {
        try {
            String algorithm = publicKey.getAlgorithm();

            if (algorithm.equals(RSA.jce())) {
                KeyFactory keyFact = KeyFactory.getInstance(algorithm, KSE.BC);
                RSAPublicKeySpec keySpec = keyFact.getKeySpec(publicKey, RSAPublicKeySpec.class);
                BigInteger modulus = keySpec.getModulus();
                return new KeyInfo(ASYMMETRIC, algorithm, modulus.toString(2).length());
            } else if (algorithm.equals(DSA.jce())) {
                KeyFactory keyFact = KeyFactory.getInstance(algorithm);
                DSAPublicKeySpec keySpec = keyFact.getKeySpec(publicKey, DSAPublicKeySpec.class);
                BigInteger prime = keySpec.getP();
                return new KeyInfo(ASYMMETRIC, algorithm, prime.toString(2).length());
            } else if (algorithm.equals(EC.jce()) || algorithm.equals(ECDSA.jce())) {
                ECPublicKey pubk = (ECPublicKey) publicKey;
                int size = pubk.getParams().getOrder().bitLength();
                return new KeyInfo(ASYMMETRIC, algorithm, size, EccUtil.getNamedCurve(publicKey));
            } else if (ED25519.jce().equalsIgnoreCase(algorithm)) {
                return new KeyInfo(ASYMMETRIC, algorithm, ED25519.bitLength());
            } else if (ED448.jce().equalsIgnoreCase(algorithm)) {
                return new KeyInfo(ASYMMETRIC, algorithm, ED448.bitLength());
            } else if (EDDSA.jce().equalsIgnoreCase(algorithm)) { // JRE 15 or higher
                EdDSACurves edDSACurve = EccUtil.detectEdDSACurve(publicKey);
                return new KeyInfo(ASYMMETRIC, edDSACurve.jce(), edDSACurve.bitLength());
            }

            return new KeyInfo(ASYMMETRIC, algorithm); // size unknown
        } catch (GeneralSecurityException ex) {
            throw new CryptoException(res.getString("NoPublicKeysize.exception.message"), ex);
        }
    }

    /**
     * Get the information about the supplied private key.
     *
     * @param privateKey The private key
     * @return Key information
     * @throws CryptoException If there is a problem getting the information
     */
    public static KeyInfo getKeyInfo(PrivateKey privateKey) throws CryptoException {
        try {
            String algorithm = privateKey.getAlgorithm();

            if (RSA.jce().equals(algorithm)) {
                if (privateKey instanceof RSAPrivateKey) {
                    // Using default provider does not work for BKS and UBER resident private keys
                    KeyFactory keyFact = KeyFactory.getInstance(algorithm, KSE.BC);
                    RSAPrivateKeySpec keySpec = keyFact.getKeySpec(privateKey, RSAPrivateKeySpec.class);
                    BigInteger modulus = keySpec.getModulus();
                    return new KeyInfo(ASYMMETRIC, algorithm, modulus.toString(2).length());
                } else {
                    return new KeyInfo(ASYMMETRIC, algorithm, 0);
                }
            } else if (DSA.jce().equals(algorithm)) {
                // Use SUN (DSA key spec not implemented for BC)
                KeyFactory keyFact = KeyFactory.getInstance(algorithm);
                DSAPrivateKeySpec keySpec = keyFact.getKeySpec(privateKey, DSAPrivateKeySpec.class);
                BigInteger prime = keySpec.getP();
                return new KeyInfo(ASYMMETRIC, algorithm, prime.toString(2).length());
            } else if (EC.jce().equals(algorithm) || ECDSA.jce().equals(algorithm)) {
                ECPrivateKey privk = (ECPrivateKey) privateKey;
                ECParameterSpec spec = privk.getParams();
                int size = spec.getOrder().bitLength();
                return new KeyInfo(ASYMMETRIC, algorithm, size, EccUtil.getNamedCurve(privateKey));
            } else if (ED25519.jce().equalsIgnoreCase(algorithm)) {
                return new KeyInfo(ASYMMETRIC, algorithm, ED25519.bitLength());
            } else if (ED448.jce().equalsIgnoreCase(algorithm)) {
                return new KeyInfo(ASYMMETRIC, algorithm, ED448.bitLength());
            } else if (EDDSA.jce().equalsIgnoreCase(algorithm)) { // JRE 15 or higher
                EdDSACurves edDSACurve = EccUtil.detectEdDSACurve(privateKey);
                return new KeyInfo(ASYMMETRIC, edDSACurve.jce(), edDSACurve.bitLength());
            }

            return new KeyInfo(ASYMMETRIC, algorithm); // size unknown
        } catch (GeneralSecurityException ex) {
            throw new CryptoException(res.getString("NoPrivateKeysize.exception.message"), ex);
        }
    }

    /**
     * Determine the key pair type (algorithm).
     *
     * @param privateKey The private key
     * @return KeyPairType type
     */
    public static KeyPairType getKeyPairType(PrivateKey privateKey) {
        return KeyPairType.resolveJce(privateKey.getAlgorithm());
    }

    /**
     * Determine the key pair type (algorithm).
     *
     * @param publicKey The private key
     * @return KeyPairType type
     */
    public static KeyPairType getKeyPairType(PublicKey publicKey) {
        return KeyPairType.resolveJce(publicKey.getAlgorithm());
    }

    /**
     * Check that the supplied private and public keys actually comprise a valid
     * key pair.
     *
     * @param privateKey Private key
     * @param publicKey  Public key
     * @return True if the private and public keys comprise a valid key pair,
     *         false otherwise.
     * @throws CryptoException If there is a problem validating the key pair
     */
    public static boolean validKeyPair(PrivateKey privateKey, PublicKey publicKey) throws CryptoException {
        try {
            String privateAlgorithm = privateKey.getAlgorithm();

            // Match private and public keys by signing some data and verifying the signature with the public key
            byte[] toSign = "Some random text".getBytes();
            if (privateAlgorithm.equals(RSA.jce())) {
                String signatureAlgorithm = "SHA256withRSA";
                byte[] signature = sign(toSign, privateKey, signatureAlgorithm);
                return verify(toSign, signature, publicKey, signatureAlgorithm);
            } else if (privateAlgorithm.equals(DSA.jce())) {
                String signatureAlgorithm = "SHA1withDSA";
                byte[] signature = sign(toSign, privateKey, signatureAlgorithm);
                return verify(toSign, signature, publicKey, signatureAlgorithm);
            } else if (privateAlgorithm.equals(EC.jce()) || privateAlgorithm.equals(ECDSA.jce())) {
                String signatureAlgorithm = "SHA256withECDSA";
                byte[] signature = sign(toSign, privateKey, signatureAlgorithm);
                return verify(toSign, signature, publicKey, signatureAlgorithm);
            } else if (privateAlgorithm.equals(ED25519.jce())) {
                byte[] signature = sign(toSign, privateKey, ED25519.jce());
                return verify(toSign, signature, publicKey, ED25519.jce());
            } else if (privateAlgorithm.equals(ED448.jce())) {
                byte[] signature = sign(toSign, privateKey, ED448.jce());
                return verify(toSign, signature, publicKey, ED448.jce());
            } else if (privateAlgorithm.equals(EDDSA.jce())) {
                EdDSACurves detectedEdDSACurve = EccUtil.detectEdDSACurve(privateKey);
                byte[] signature = sign(toSign, privateKey, detectedEdDSACurve.jce());
                return verify(toSign, signature, publicKey, detectedEdDSACurve.jce());
            } else {
                throw new CryptoException(
                        MessageFormat.format(res.getString("NoCheckCompriseValidKeypairAlg.exception.message"),
                                             privateAlgorithm));
            }
        } catch (GeneralSecurityException ex) {
            throw new CryptoException(res.getString("NoCheckCompriseValidKeypair.exception.message"), ex);
        }
    }

    private static byte[] sign(byte[] toSign, PrivateKey privateKey, String signatureAlgorithm)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance(signatureAlgorithm, KSE.BC);
        signature.initSign(privateKey);
        signature.update(toSign);
        return signature.sign();
    }

    private static boolean verify(byte[] signed, byte[] signatureToVerify, PublicKey publicKey,
                                  String signatureAlgorithm) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(signatureAlgorithm, KSE.BC);
        signature.initVerify(publicKey);
        signature.update(signed);
        return signature.verify(signatureToVerify);
    }
}
