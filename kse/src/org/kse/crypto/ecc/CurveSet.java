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
package org.kse.crypto.ecc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.kse.crypto.keystore.KeyStoreType;

/**
 * Enumeration for all currently available ECC named curve sets.
 *
 */
public enum CurveSet {

	ANSI_X9_62("ANSI X9.62"),
	NIST("NIST"),
	SEC("SEC"),
	TELETRUST("Brainpool");

	private String visibleName;

	CurveSet(String visibleName) {
		this.visibleName = visibleName;
	}

	/**
	 * Return list with all curve set name that are available for the given KeyStoreType.
	 *
	 * @return All available sets of named curves
	 */
	public static String[] getAvailableSetNames(KeyStoreType keyStoreType) {
		List<String> sets = new ArrayList<String>();
		sets.add(ANSI_X9_62.visibleName);
		sets.add(NIST.visibleName);
		sets.add(SEC.visibleName);
		if (EccUtil.isBouncyCastleKeyStore(keyStoreType)) {
			sets.add(TELETRUST.visibleName);
		}
		return sets.toArray(new String[sets.size()]);
	}

	/**
	 * Return list with all curve sets that are available for the given KeyStoreType.
	 *
	 * @return All available sets of named curves
	 */
	public static List<CurveSet> getAvailableSets(KeyStoreType keyStoreType) {
		List<CurveSet> sets = new ArrayList<CurveSet>();
		sets.add(ANSI_X9_62);
		sets.add(NIST);
		sets.add(SEC);
		if (EccUtil.isBouncyCastleKeyStore(keyStoreType)) {
			sets.add(TELETRUST);
		}
		return sets;
	}

	/**
	 * Return the list of available curve names for this set.
	 *
	 * @return The named curves that belong to this set
	 */
	public List<String> getAvailableCurveNames(KeyStoreType keyStoreType) {

		// filter out unsupported curves
		List<String> curveNames = getAllCurveNames();
		Iterator<String> it = curveNames.iterator();
		while (it.hasNext()) {
			String curveName = it.next();
			if (!EccUtil.isCurveAvailable(curveName, keyStoreType)) {
				it.remove();
			}
		}

		return curveNames;
	}


	/**
	 * Return the list of all curve names for this set.
	 *
	 * @return The named curves that belong to this set
	 */
	@SuppressWarnings("unchecked")
	public List<String> getAllCurveNames() {
		Enumeration<String> en = null;

		switch (this) {
		case ANSI_X9_62:
			en = X962NamedCurves.getNames();
			break;
		case TELETRUST:
			en = TeleTrusTNamedCurves.getNames();
			break;
		case NIST:
			en = NISTNamedCurves.getNames();
			break;
		case SEC:
			en = SECNamedCurves.getNames();
			break;
		}

		if (en == null) {
			return new ArrayList<String>();
		}

		return Collections.list(en);
	}

	/**
	 * Resolve curve set name to a CurveSet instance.
	 *
	 * @param curveSetName Name of the curve set
	 * @return CurveSet instance or null if no match found
	 */
	public static CurveSet resolveName(String curveSetName) {
		if (curveSetName == null) {
			return null;
		}

		if (curveSetName.equals(SEC.visibleName)) {
			return SEC;
		} else if (curveSetName.equals(NIST.visibleName)) {
			return NIST;
		} else if (curveSetName.equals(ANSI_X9_62.visibleName)) {
			return ANSI_X9_62;
		} else if (curveSetName.equals(TELETRUST.visibleName)) {
			return TELETRUST;
		}

		return null;
	}

	/**
	 * Get set name for use in GUI elements
	 * @return Set name
	 */
	public String getVisibleName() {
		return visibleName;
	}
}
