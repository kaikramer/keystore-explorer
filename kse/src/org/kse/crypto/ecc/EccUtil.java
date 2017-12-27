/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
package org.kse.crypto.ecc;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.version.JavaVersion;

/**
 * Static helper methods for ECC stuff, mainly detection of available ECC algorithms.
 *
 */
public class EccUtil {

	private static boolean sunECProviderAvailable = true;
	private static String[] availableSunCurves = new String[0];
	static {
		// read available curves provided by SunEC
		Provider sunECProvider = Security.getProvider("SunEC");
		if (sunECProvider != null) {
			availableSunCurves = sunECProvider.getProperty("AlgorithmParameters.EC SupportedCurves").split("\\|");
		} else {
			sunECProviderAvailable = false;
		}
	}

	/**
	 * Determines the name of the domain parameters that were used for generating the key.
	 *
	 * @param key An EC key
	 * @return The name of the domain parameters that were used for the EC key,
	 *         or an empty string if curve is unknown.
	 */
	public static String getNamedCurve(Key key) {

		if (!(key instanceof ECKey)) {
			throw new InvalidParameterException("Not a EC private key.");
		}

		ECKey ecKey = (ECKey) key;
		ECParameterSpec params = ecKey.getParams();
		if (!(params instanceof ECNamedCurveSpec)) {
			return "";
		}

		ECNamedCurveSpec ecPrivateKeySpec = (ECNamedCurveSpec) params;
		String namedCurve = ecPrivateKeySpec.getName();
		return namedCurve;
	}

	/**
	 * Checks if EC curves are available for the given keyStoreType
	 * (i.e. either BC key store type or at least Java 7)
	 *
	 * @param keyStoreType Availability depends on store type
	 * @return True, if there are EC curves available
	 */
	public static boolean isECAvailable(KeyStoreType keyStoreType) {
		return ((JavaVersion.getJreVersion().isAtLeast(JavaVersion.JRE_VERSION_170) && sunECProviderAvailable)
				|| isBouncyCastleKeyStore(keyStoreType));
	}

	/**
	 * Is the given KeyStoreType backed by the BC provider?
	 *
	 * @param keyStoreType KeyStoreType to check
	 * @return True, if KeyStoreType is backed by the BC provider
	 */
	public static boolean isBouncyCastleKeyStore(KeyStoreType keyStoreType) {
		return (keyStoreType == KeyStoreType.BKS
				|| keyStoreType == KeyStoreType.BKS_V1
				|| keyStoreType == KeyStoreType.UBER);
	}

	/**
	 * Checks if the given named curve is known by the provider backing the KeyStoreType.
	 *
	 * @param curveName Name of the curve
	 * @param keyStoreType KeyStoreType
	 * @return True, if named curve is supported by the keystore
	 */
	public static boolean isCurveAvailable(String curveName, KeyStoreType keyStoreType) {

		// BC provides all curves
		if (isBouncyCastleKeyStore(keyStoreType)) {
			return true;
		}

		// no SunEC provider found?
		if (availableSunCurves.length == 0) {
			return false;
		}

		// is curve among SunEC curves?
		for (String curve : availableSunCurves) {
			if (curve.contains(curveName)) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Finds the longest curve name in all curves that are provided by BC.
	 *
	 * @return String with longest curve name
	 */
	public static String findLongestCurveName() {
		String longestCurveName = "";
		for (CurveSet curveSet : CurveSet.values()) {
			List<String> curveNames = curveSet.getAllCurveNames();
			for (String curveName : curveNames) {
				if (curveName.length() > longestCurveName.length()) {
					longestCurveName = curveName;
				}
			}
		}
		return longestCurveName;
	}

	/**
	 * Converts PKCS#8 EC private key (RFC 5208 ASN.1 PrivateKeyInfo structure) to "traditional" OpenSSL
	 * ASN.1 structure ECPrivateKey from RFC 5915.
	 *
	 * @param ecPrivateKey An EC key
	 * @return Object holding ASN1 ECPrivateKey structure
	 */
	public static org.bouncycastle.asn1.sec.ECPrivateKey convertToECPrivateKeyStructure(ECPrivateKey ecPrivateKey) {
		ECParameterSpec ecSpec = ecPrivateKey.getParams();
		BigInteger s = ecPrivateKey.getS();
		int orderBitLength = ecSpec.getOrder().bitLength();

		X962Parameters params = null;
		if (ecSpec instanceof ECNamedCurveSpec) {
			ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec) ecSpec).getName());
			if (curveOid == null) {
				curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec) ecSpec).getName());
			}
			params = new X962Parameters(curveOid);
		} else {
			ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());
			X9ECParameters ecP = new X9ECParameters(curve,
					EC5Util.convertPoint(curve, ecSpec.getGenerator(), false), ecSpec.getOrder(),
					BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());
			params = new X962Parameters(ecP);
		}

		org.bouncycastle.asn1.sec.ECPrivateKey keyStructure =
				new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLength, s, params);
		return keyStructure;
	}
}
