/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
import static org.kse.crypto.SecurityProvider.BOUNCY_CASTLE;
import static org.kse.crypto.keypair.KeyPairType.DSA;
import static org.kse.crypto.keypair.KeyPairType.EC;
import static org.kse.crypto.keypair.KeyPairType.ECDSA;
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
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;

/**
 * Provides utility methods relating to asymmetric key pairs.
 *
 */
public final class KeyPairUtil {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/keypair/resources");

	private KeyPairUtil() {
	}

	/**
	 * Generate a key pair.
	 *
	 * @param keyPairType
	 *            Key pair type to generate
	 * @param keySize
	 *            Key size of key pair
	 * @return A keypair
	 * @param provider
	 *         Crypto provider used for key generation
	 * @throws CryptoException
	 *             If there was a problem generating the key pair
	 */
	public static KeyPair generateKeyPair(KeyPairType keyPairType, int keySize, Provider provider) throws CryptoException {
		try {
			// Get a key pair generator
			KeyPairGenerator keyPairGen = null;

			if (provider != null) {
				keyPairGen = KeyPairGenerator.getInstance(keyPairType.jce(), provider);
			} else {
				// Always use BC provider for RSA
				if (keyPairType == RSA) {
					keyPairGen = KeyPairGenerator.getInstance(keyPairType.jce(), BOUNCY_CASTLE.jce());
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
			KeyPair keyPair = keyPairGen.generateKeyPair();
			return keyPair;
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoGenerateKeypair.exception.message"),
					keyPairType), ex);
		}
	}

	/**
	 * Generate a EC key pair.
	 *
	 * @param curveName
	 *            Name of the ECC curve
	 * @param provider A JCE provider.
	 * @return A key pair
	 * @throws CryptoException
	 *             If there was a problem generating the key pair
	 */
	public static KeyPair generateECKeyPair(String curveName, Provider provider) throws CryptoException {
		try {
			// Get a key pair generator
			KeyPairGenerator keyPairGen;
			if (provider != null) {
				keyPairGen = KeyPairGenerator.getInstance(KeyPairType.EC.jce(), provider);
			} else {
				keyPairGen = KeyPairGenerator.getInstance(KeyPairType.EC.jce(), BOUNCY_CASTLE.jce());
			}

			keyPairGen.initialize(new ECGenParameterSpec(curveName), SecureRandom.getInstance("SHA1PRNG"));

			// Generate and return the key pair
			KeyPair keyPair = keyPairGen.generateKeyPair();
			return keyPair;
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(MessageFormat.format(res.getString("NoGenerateKeypair.exception.message"),
					KeyPairType.EC), ex);
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
	 * @param publicKey
	 *            The public key
	 * @return Key information
	 * @throws CryptoException
	 *             If there is a problem getting the information
	 */
	public static KeyInfo getKeyInfo(PublicKey publicKey) throws CryptoException {
		try {
			String algorithm = publicKey.getAlgorithm();

			if (algorithm.equals(RSA.jce())) {
				KeyFactory keyFact = KeyFactory.getInstance(algorithm, BOUNCY_CASTLE.jce());
				RSAPublicKeySpec keySpec = keyFact.getKeySpec(publicKey, RSAPublicKeySpec.class);
				BigInteger modulus = keySpec.getModulus();
				return new KeyInfo(ASYMMETRIC, algorithm, modulus.toString(2).length());
			} else if (algorithm.equals(DSA.jce())) {
				KeyFactory keyFact = KeyFactory.getInstance(algorithm);
				DSAPublicKeySpec keySpec = keyFact.getKeySpec(publicKey, DSAPublicKeySpec.class);
				BigInteger prime = keySpec.getP();
				return new KeyInfo(ASYMMETRIC, algorithm, prime.toString(2).length());
			} else if (algorithm.equals(EC.jce())) {
				ECPublicKey pubk = (ECPublicKey) publicKey;
				int size = pubk.getParams().getOrder().bitLength();
				return new KeyInfo(ASYMMETRIC, algorithm, size);
			}

			return new KeyInfo(ASYMMETRIC, algorithm); // size unknown
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoPublicKeysize.exception.message"), ex);
		}
	}

	/**
	 * Get the information about the supplied private key.
	 *
	 * @param privateKey
	 *            The private key
	 * @return Key information
	 * @throws CryptoException
	 *             If there is a problem getting the information
	 */
	public static KeyInfo getKeyInfo(PrivateKey privateKey) throws CryptoException {
		try {
			String algorithm = privateKey.getAlgorithm();

			if (algorithm.equals(RSA.jce())) {
				if (privateKey instanceof RSAPrivateKey) {
					// Using default provider does not work for BKS and UBER resident private keys
					KeyFactory keyFact = KeyFactory.getInstance(algorithm, BOUNCY_CASTLE.jce());
					RSAPrivateKeySpec keySpec = keyFact.getKeySpec(privateKey,
							RSAPrivateKeySpec.class);
					BigInteger modulus = keySpec.getModulus();
					return new KeyInfo(ASYMMETRIC, algorithm, modulus.toString(2).length());
				} else {
					return new KeyInfo(ASYMMETRIC, algorithm, 0);
				}
			} else if (algorithm.equals(DSA.jce())) {
				// Use SUN (DSA key spec not implemented for BC)
				KeyFactory keyFact = KeyFactory.getInstance(algorithm);
				DSAPrivateKeySpec keySpec = keyFact.getKeySpec(privateKey, DSAPrivateKeySpec.class);
				BigInteger prime = keySpec.getP();
				return new KeyInfo(ASYMMETRIC, algorithm, prime.toString(2).length());
			} else if (algorithm.equals(EC.jce()) || algorithm.equals(ECDSA.jce())) {
				ECPrivateKey pubk = (ECPrivateKey) privateKey;
				int size = pubk.getParams().getOrder().bitLength();
				return new KeyInfo(ASYMMETRIC, algorithm, size);
			}

			return new KeyInfo(ASYMMETRIC, algorithm); // size unknown
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoPrivateKeysize.exception.message"), ex);
		}
	}

	/**
	 * Determine the key pair type (algorithm).
	 *
	 * @param privateKey
	 *            The private key
	 * @return KeyPairType type
	 */
	public static KeyPairType getKeyPairType(PrivateKey privateKey)  {
		return KeyPairType.resolveJce(privateKey.getAlgorithm());
	}

	/**
	 * Check that the supplied private and public keys actually comprise a valid
	 * key pair.
	 *
	 * @param privateKey
	 *            Private key
	 * @param publicKey
	 *            Public key
	 * @return True if the private and public keys comprise a valid key pair,
	 *         false otherwise.
	 * @throws CryptoException
	 *             If there is a problem validating the key pair
	 */
	public static boolean validKeyPair(PrivateKey privateKey, PublicKey publicKey) throws CryptoException {
		try {
			String privateAlgorithm = privateKey.getAlgorithm();

			String publicAlgorithm = publicKey.getAlgorithm();

			if (!privateAlgorithm.equals(publicAlgorithm)) {
				return false;
			}

			// Match private and public keys by signing some data with the
			// private key and verifying the signature with the public key
			if (privateAlgorithm.equals(RSA.jce())) {
				byte[] toSign = "Rivest Shamir Adleman".getBytes();
				String signatureAlgorithm = "SHA256withRSA";
				byte[] signature = sign(toSign, privateKey, signatureAlgorithm);

				return verify(toSign, signature, publicKey, signatureAlgorithm);
			} else if (privateAlgorithm.equals(DSA.jce())) {
				byte[] toSign = "Digital Signature Algorithm".getBytes();
				String signatureAlgorithm = "SHA1withDSA";
				byte[] signature = sign(toSign, privateKey, signatureAlgorithm);

				return verify(toSign, signature, publicKey, signatureAlgorithm);
			} else if (privateAlgorithm.equals(EC.jce())) {
				byte[] toSign = "EC Digital Signature Algorithm".getBytes();
				String signatureAlgorithm = "SHA256withECDSA";
				byte[] signature = sign(toSign, privateKey, signatureAlgorithm);

				return verify(toSign, signature, publicKey, signatureAlgorithm);
			} else {
				throw new CryptoException(MessageFormat.format(
						res.getString("NoCheckCompriseValidKeypairAlg.exception.message"), privateAlgorithm));
			}
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoCheckCompriseValidKeypair.exception.message"), ex);
		}
	}

	private static byte[] sign(byte[] toSign, PrivateKey privateKey, String signatureAlgorithm)
			throws GeneralSecurityException {
		Signature signature = Signature.getInstance(signatureAlgorithm, new BouncyCastleProvider());
		signature.initSign(privateKey);
		signature.update(toSign);
		return signature.sign();
	}

	private static boolean verify(byte[] signed, byte[] signaureToVerify, PublicKey publicKey, String signatureAlgorithm)
			throws GeneralSecurityException {
		Signature signature = Signature.getInstance(signatureAlgorithm, new BouncyCastleProvider());
		signature.initVerify(publicKey);
		signature.update(signed);
		return signature.verify(signaureToVerify);
	}
}
