/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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
package org.kse.version;

import java.io.Serializable;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

/**
 * Immutable version class constructed from a version string. Used to compare
 * versions. Only allows for simple versions strings made up of >= 0 integers
 * separated by dots or something similar.
 *
 */
public class Version implements Comparable<Object>, Serializable {
	private static final long serialVersionUID = 775513157889646154L;
	private static transient ResourceBundle res = ResourceBundle.getBundle("org/kse/version/resources");
	private List<Integer> iSections;

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
	public Version(String version, String delimiters) {

		StringTokenizer strTok = new StringTokenizer(version.trim(), delimiters);
		List<Integer> versionSections = new ArrayList<>();

		while (strTok.hasMoreTokens()) {
			try {
				int i = Integer.parseInt(strTok.nextToken());

				if (i < 0) {
					throw new VersionException(MessageFormat.format(res.getString("NoParseVersion.exception.message"),
							version, delimiters));
				}
				versionSections.add(i);
			} catch (NumberFormatException ex) {
				throw new VersionException(MessageFormat.format(res.getString("NoParseVersion.exception.message"),
						version, delimiters));
			}
		}

		if (versionSections.isEmpty()) {
			throw new VersionException(MessageFormat.format(res.getString("NoParseVersion.exception.message"),
					version, delimiters));
		} else {
			iSections = versionSections;
		}
	}

	private List<Integer> getSections() {
		return new ArrayList<>(iSections);
	}

	@Override
	public int compareTo(Object object) {
		Version cmpVersion = (Version) object;

		List<Integer> cmpSections = cmpVersion.getSections();

		for (int i = 0; ((i < iSections.size()) && (i < cmpSections.size())); i++) {
			if (iSections.get(i) > cmpSections.get(i)) {
				return 1;
			} else if (iSections.get(i) < cmpSections.get(i)) {
				return -1;
			}
		}

		if (cmpSections.size() > iSections.size()) {
			for (int i = iSections.size(); i < cmpSections.size(); i++) {
				if (cmpSections.get(i) != 0) {
					return -1;
				}
			}
		}

		if (iSections.size() > cmpSections.size()) {
			for (int i = cmpSections.size(); i < iSections.size(); i++) {
				if (iSections.get(i) != 0) {
					return 1;
				}
			}
		}

		return 0;
	}

	/**
	 * Gets major version (first part of a version string, e.g. for version "1.2.3" it returns "1")
	 * @return Major version
	 */
	public int getMajor() {
		return iSections.get(0);
	}

	/**
	 * Gets minor version (second part of a version string, e.g. for version "1.2.3" it returns "2")
	 * @return Minor version or 0 if there is none
	 */
	public int getMinor() {
		if (iSections.size() > 1) {
			return iSections.get(1);
		} else {
			return 0;
		}
	}

	/**
	 * Gets bug fix version (third part of a version string, e.g. for version "1.2.3" it returns "3")
	 * @return Bug fix version or 0 if there is none
	 */
	public int getBugfix() {
		if (iSections.size() > 2) {
			return iSections.get(2);
		} else {
			return 0;
		}
	}

	@Override
	public boolean equals(Object object) {
		if (object == this) {
			return true;
		}

		if (!(object instanceof Version)) {
			return false;
		}

		return compareTo(object) == 0;

	}

	@Override
	public int hashCode() {
		int result = 27;

		for (Integer integer : iSections) {
			result = 53 * result + integer;
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
	@Override
	public String toString() {
		StringBuilder strBuff = new StringBuilder();

		for (int i = 0; i < iSections.size(); i++) {
			strBuff.append(iSections.get(i));

			if ((i + 1) < iSections.size()) {
				strBuff.append('.');
			}
		}

		return strBuff.toString();
	}
}
