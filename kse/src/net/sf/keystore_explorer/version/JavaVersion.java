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
package net.sf.keystore_explorer.version;

import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

// @formatter:off
/**
 * Immutable version class constructed from a Java version string. The Java
 * version takes the form:
 * <p>
 * major.middle.minor[_update][-identifier]
 * <p>
 * or if Oracle is ignoring its own rules:
 * <p>
 * major.middle.minor[.update][-identifier]
 * <p>
 * Object's of this class can be used to compare Java different versions. Note
 * that for the purposes of comparison the identifier is considered only in so
 * much as it is present or not - its actual value is unimportant. Therefore for
 * two otherwise identical versions the presence of an identifier in one will
 * make it a lower version than the other. This is because standard identifier
 * values have not been identified by Oracle.
 *
 */
// @formatter:on
public class JavaVersion implements Comparable {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/version/resources");
	private String javaVersion;
	private int major;
	private int middle;
	private int minor;
	private int update;
	private String identifier;
	private char VERSION_DELIMITER = '.';
	private char START_UPDATE = '_';
	private char START_IDENTIFIER = '-';
	private static JavaVersion jreVersion;

	/** JRE version 1.3.0 */
	public static final JavaVersion JRE_VERSION_130 = new JavaVersion("1.3.0");

	/** JRE version 1.4.0 */
	public static final JavaVersion JRE_VERSION_140 = new JavaVersion("1.4.0");

	/** JRE version 1.5.0 */
	public static final JavaVersion JRE_VERSION_150 = new JavaVersion("1.5.0");

	/** JRE version 1.6.0 */
	public static final JavaVersion JRE_VERSION_160 = new JavaVersion("1.6.0");

	/** JRE version 1.7.0 */
	public static final JavaVersion JRE_VERSION_170 = new JavaVersion("1.7.0");

	/** JRE version 1.8.0 */
	public static final JavaVersion JRE_VERSION_180 = new JavaVersion("1.8.0");

	/** JRE version 1.9.0 */
	public static final JavaVersion JRE_VERSION_190 = new JavaVersion("1.9.0");

	/**
	 * Construct a JavaVersion object for the current Java environment.
	 *
	 * @throws VersionException
	 *             If the Java version string cannot be parsed
	 */
	public JavaVersion() throws VersionException {
		this(System.getProperty("java.version"));
	}

	/**
	 * Construct a JavaVersion object from the supplied string.
	 *
	 * @param javaVersion
	 *            The Java version string
	 * @throws VersionException
	 *             If the Java version string cannot be parsed
	 */
	public JavaVersion(String javaVersion) throws VersionException {
		this.javaVersion = javaVersion;

		// Count version delimiters
		int versionDelimiters = 0;
		int lastIndex = 0;

		while ((lastIndex = javaVersion.indexOf(VERSION_DELIMITER, lastIndex + 1)) != -1) {
			versionDelimiters++;
		}

		// Get index for update - will be found differently depending on whether
		// or not Oracle have followed their rules concerning delimiting update
		// identifiers

		int indexUpdate;

		if (versionDelimiters == 3) {
			// Broken rule - update is delimited incorrectly:
			// major.middle.minor[.update][-identifier]
			indexUpdate = javaVersion.lastIndexOf(VERSION_DELIMITER);
		} else {
			// Unbroken rule - update is delimited correctly if present:
			// major.middle.minor[_update][-identifier]
			indexUpdate = javaVersion.indexOf(START_UPDATE);
		}

		// Get index for identifier

		int indexIdentifier = javaVersion.indexOf(START_IDENTIFIER);

		// Defaults for version, update and identifier
		String versionRead = null;
		String updateRead = "0";
		String identifierRead = null;

		// No update nor identifier
		if (indexUpdate == -1 && indexIdentifier == -1) {
			versionRead = javaVersion; // Version as a string
		}
		// Update but no identifier
		else if (indexUpdate != -1 && indexIdentifier == -1) {
			versionRead = javaVersion.substring(0, indexUpdate); // Version as a string
			updateRead = javaVersion.substring(indexUpdate + 1); // Update as a string
		}
		// Identifier but no update
		else if (indexUpdate == -1) {
			versionRead = javaVersion.substring(0, indexIdentifier); // Version as a string
			identifierRead = javaVersion.substring(indexIdentifier + 1); // Identifier as a string
		}
		// Update and identifier
		else {
			versionRead = javaVersion.substring(0, indexUpdate); // Version as a string
			updateRead = javaVersion.substring(indexUpdate + 1, indexIdentifier); // Update as a string
			identifierRead = javaVersion.substring(indexIdentifier + 1); // Identifier as a string
		}

		// Parse version string for major, middle and minor version numbers
		StringTokenizer strTok = new StringTokenizer(versionRead, "" + VERSION_DELIMITER);

		if (strTok.countTokens() != 3) {
			// Don't have all three versions
			throw new VersionException(MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"),
					javaVersion));
		}

		// Get major version
		String majorRead = strTok.nextToken();
		try {
			major = Integer.parseInt(majorRead);
		} catch (NumberFormatException ex) {
			throw new VersionException(MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"),
					javaVersion));
		}

		if (major < 0) {
			throw new VersionException(MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"),
					javaVersion));
		}

		// Get middle version
		String middleRead = strTok.nextToken();
		try {
			middle = Integer.parseInt(middleRead);
		} catch (NumberFormatException ex) {
			throw new VersionException(MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"),
					javaVersion));
		}

		if (middle < 0) {
			throw new VersionException(MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"),
					javaVersion));
		}

		// Get minor version
		String minorRead = strTok.nextToken();
		try {
			minor = Integer.parseInt(minorRead);
		} catch (NumberFormatException ex) {
			throw new VersionException(MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"),
					javaVersion));
		}

		if (minor < 0) {
			throw new VersionException(MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"),
					javaVersion));
		}

		// Get update version
		try {
			update = Integer.parseInt(updateRead);
		} catch (NumberFormatException ex) {
			throw new VersionException(MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"),
					javaVersion));
		}

		if (update < 0) {
			throw new VersionException(MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"),
					javaVersion));
		}

		// Get identifier (if any)
		this.identifier = identifierRead;
	}

	/**
	 * Get Java version's major number.
	 *
	 * @return Minor number
	 */
	public int getMajor() {
		int major = this.major;
		return major;
	}

	/**
	 * Get Java version's middle number.
	 *
	 * @return Minor number
	 */
	public int getMiddle() {
		int middle = this.middle;
		return middle;
	}

	/**
	 * Get Java version's minor number.
	 *
	 * @return Minor number
	 */
	public int getMinor() {
		int minor = this.minor;
		return minor;
	}

	/**
	 * Get Java version's update number.
	 *
	 * @return Update number or 0 if none
	 */
	public int getUpdate() {
		int update = this.update;
		return update;
	}

	/**
	 * Get Java version's identifier.
	 *
	 * @return Identifier or null if none
	 */
	public String getIdentifier() {
		if (identifier == null) {
			return null;
		}

		return identifier;
	}

	/**
	 * Get the current JRE version.
	 *
	 * @return The JRE version.
	 * @throws VersionException
	 *             If JRE's version is not parseable
	 */
	public static JavaVersion getJreVersion() throws VersionException {
		if (jreVersion == null) {
			String jreVersionProp = System.getProperty("java.version");

			jreVersion = new JavaVersion(jreVersionProp);
		}

		return jreVersion;
	}

	/**
	 * Compares version of the current JRE with the passed version.
	 *
	 * @param javaVersion
	 *             Java version to compare to.
	 * @return True, if current JRE is same version or higher.
	 */
	public boolean isAtLeast(JavaVersion javaVersion) {
		return compareTo(javaVersion) >= 0;
	}

	@Override
	public int compareTo(Object object) throws ClassCastException {
		JavaVersion cmpJavaVersion = (JavaVersion) object;

		if (major > cmpJavaVersion.getMajor()) {
			return 1;
		} else if (major < cmpJavaVersion.getMajor()) {
			return -1;
		}

		if (middle > cmpJavaVersion.getMiddle()) {
			return 1;
		} else if (middle < cmpJavaVersion.getMiddle()) {
			return -1;
		}

		if (minor > cmpJavaVersion.getMinor()) {
			return 1;
		} else if (minor < cmpJavaVersion.getMinor()) {
			return -1;
		}

		if (update > cmpJavaVersion.getUpdate()) {
			return 1;
		} else if (update < cmpJavaVersion.getUpdate()) {
			return -1;
		}

		return 0;
	}

	@Override
	public boolean equals(Object object) {
		if (object == this) {
			return true;
		}

		if (!(object instanceof JavaVersion)) {
			return false;
		}

		return compareTo(object) == 0;

	}

	@Override
	public int hashCode() {
		int result = 27;

		result = 53 * result + major;
		result = 53 * result + middle;
		result = 53 * result + minor;
		result = 53 * result + update;
		result = 53 * result + (identifier == null ? 0 : 1);

		return result;
	}

	@Override
	public String toString() {
		return javaVersion;
	}
}
