/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2014 Kai Kramer
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
package net.sf.keystore_explorer.version;

import java.io.Serializable;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Vector;

/**
 * Immutable version class constructed from a version string. Used to compare
 * versions. Only allows for simple versions strings made up of >= 0 integers
 * separated by dots or something similar.
 * 
 */
public class Version implements Comparable, Serializable {
	private static final long serialVersionUID = 775513157889646154L; 
	private static transient ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/version/resources");
	private int[] iSections;

	/**
	 * Construct a Version object from the supplied string assuming that the
	 * string delimiter used is '.'.
	 * 
	 * @param version
	 *            The version string.
	 * @throws VersionException
	 *             If the version string cannot be parsed.
	 */
	public Version(String version) throws VersionException {
		this(version, ".");
	}

	/**
	 * Construct a Version object from the supplied string and delimiters.
	 * 
	 * @param version
	 *            The version string.
	 * @param delimiters
	 *            The delimiters.
	 * @throws VersionException
	 *             If the version string cannot be parsed.
	 */
	public Version(String version, String delimiters) throws VersionException {
		StringTokenizer strTok = new StringTokenizer(version, delimiters);

		Vector<Integer> versionSections = new Vector<Integer>();

		while (strTok.hasMoreTokens()) {
			try {
				Integer i = new Integer(strTok.nextToken());

				if (i.intValue() < 0) {
					throw new VersionException(MessageFormat.format(res.getString("NoParseVersion.exception.message"),
							version, delimiters));
				}
				versionSections.add(i);
			} catch (NumberFormatException ex) {
				throw new VersionException(MessageFormat.format(res.getString("NoParseVersion.exception.message"),
						version, delimiters));
			}
		}

		if (versionSections.size() == 0) {
			iSections = new int[] { 0 };
		} else {
			iSections = new int[versionSections.size()];

			for (int i = 0; i < versionSections.size(); i++) {
				iSections[i] = Math.abs(versionSections.get(i).intValue());
			}
		}
	}

	private int[] getSections() {
		return (int[]) iSections.clone();
	}

	public int compareTo(Object object) {
		Version cmpVersion = (Version) object;

		int[] cmpSections = cmpVersion.getSections();

		for (int i = 0; ((i < iSections.length) && (i < cmpSections.length)); i++) {
			if (iSections[i] > cmpSections[i]) {
				return 1;
			} else if (iSections[i] < cmpSections[i]) {
				return -1;
			}
		}

		if (cmpSections.length > iSections.length) {
			for (int i = iSections.length; i < cmpSections.length; i++) {
				if (cmpSections[i] != 0) {
					return -1;
				}
			}
		}

		if (iSections.length > cmpSections.length) {
			for (int i = cmpSections.length; i < iSections.length; i++) {
				if (iSections[i] != 0) {
					return 1;
				}
			}
		}

		return 0;
	}

	public boolean equals(Object object) {
		if (object == this) {
			return true;
		}

		if (!(object instanceof Version)) {
			return false;
		}

		if (compareTo(object) == 0) {
			return true;
		}

		return false;
	}

	public int hashCode() {
		int result = 27;

		for (int i = 0; i < iSections.length; i++) {
			result = 53 * result + iSections[i];
		}

		return result;
	}

	/**
	 * Get a string representation of the version. This will always be '.'
	 * delimited. Trailing 0's originally supplied on construction will be
	 * included.
	 * 
	 * @return A string representation of the version.
	 */
	public String toString() {
		StringBuffer strBuff = new StringBuffer();

		for (int i = 0; i < iSections.length; i++) {
			strBuff.append(iSections[i]);

			if ((i + 1) < iSections.length) {
				strBuff.append('.');
			}
		}

		return strBuff.toString();
	}
}
