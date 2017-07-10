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
package net.sf.keystore_explorer.crypto.ecc;

import java.security.InvalidParameterException;
import java.security.Key;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import java.util.List;

import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import net.sf.keystore_explorer.crypto.keystore.KeyStoreType;
import net.sf.keystore_explorer.version.JavaVersion;

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
}
