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
package org.kse.version;

import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// @formatter:off
/**
 * Immutable version class constructed from a Java version string. The Java
 * version takes the form:
 * <p>
 * major.middle.minor[_update][-identifier]
 * <p>
 * Object's of this class can be used to compare Java different versions.
 */
// @formatter:on
public class JavaVersion implements Comparable<Object> {

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/version/resources");

    private String javaVersion;

    private int major;
    private int minor;
    private int security;

    private static final String VERSION_NUMBER_REGEXP = "([0-9]+(?:\\.[0-9]*)*)";
    private static final String REST_REGEXP = "(?:[_\\-\\.\\+a-zA-Z0-9]*)";
    private static final String VERSION_FORMAT = "^" + VERSION_NUMBER_REGEXP + REST_REGEXP + "$";
    private static final Pattern VERSION_STRING_PATTERN = Pattern.compile(VERSION_FORMAT);

    private static JavaVersion jreVersion;

    public static final JavaVersion JRE_VERSION_130 = new JavaVersion("1.3.0");
    public static final JavaVersion JRE_VERSION_140 = new JavaVersion("1.4.0");
    public static final JavaVersion JRE_VERSION_150 = new JavaVersion("1.5.0");
    public static final JavaVersion JRE_VERSION_160 = new JavaVersion("1.6.0");
    public static final JavaVersion JRE_VERSION_170 = new JavaVersion("1.7.0");
    public static final JavaVersion JRE_VERSION_180 = new JavaVersion("1.8.0");
    public static final JavaVersion JRE_VERSION_9 = new JavaVersion("9");
    public static final JavaVersion JRE_VERSION_10 = new JavaVersion("10");
    public static final JavaVersion JRE_VERSION_11 = new JavaVersion("11");
    public static final JavaVersion JRE_VERSION_12 = new JavaVersion("12");
    public static final JavaVersion JRE_VERSION_13 = new JavaVersion("13");
    public static final JavaVersion JRE_VERSION_14 = new JavaVersion("14");
    public static final JavaVersion JRE_VERSION_15 = new JavaVersion("15");
    public static final JavaVersion JRE_VERSION_16 = new JavaVersion("16");
    public static final JavaVersion JRE_VERSION_17 = new JavaVersion("17");
    public static final JavaVersion JRE_VERSION_18 = new JavaVersion("18");
    public static final JavaVersion JRE_VERSION_19 = new JavaVersion("19");
    public static final JavaVersion JRE_VERSION_20 = new JavaVersion("20");
    public static final JavaVersion JRE_VERSION_21 = new JavaVersion("21");
    public static final JavaVersion JRE_VERSION_22 = new JavaVersion("22");
    public static final JavaVersion JRE_VERSION_23 = new JavaVersion("23");
    public static final JavaVersion JRE_VERSION_24 = new JavaVersion("24");

    /**
     * Construct a JavaVersion object for the current Java environment.
     *
     * @throws VersionException If the Java version string cannot be parsed
     */
    public JavaVersion() {
        this(System.getProperty("java.version"));
    }

    /**
     * Construct a JavaVersion object from the supplied string.
     *
     * @param javaVersion The Java version string
     * @throws VersionException If the Java version string cannot be parsed
     */
    public JavaVersion(String javaVersion) {
        this.javaVersion = javaVersion;

        Matcher matcher = VERSION_STRING_PATTERN.matcher(javaVersion);
        if (!matcher.matches()) {
            throw new VersionException(
                    MessageFormat.format(res.getString("NoParseJavaVersion.exception.message"), javaVersion));
        }

        String vnum = matcher.group(1);
        Version version = new Version(vnum);

        this.major = version.getMajor();
        this.minor = version.getMinor();
        this.security = version.getBugfix();
    }

    /**
     * Get Java version's major number.
     *
     * @return Minor number
     */
    public int getMajor() {
        return this.major;
    }

    /**
     * Get Java version's minor number.
     *
     * @return Minor number
     */
    public int getMinor() {
        return this.minor;
    }

    /**
     * Get Java version's security number.
     *
     * @return Minor number
     */
    public int getSecurity() {
        return this.security;
    }

    /**
     * Get the current JRE version.
     *
     * @return The JRE version.
     * @throws VersionException If JRE's version is not parseable
     */
    public static JavaVersion getJreVersion() {
        if (jreVersion == null) {
            String jreVersionProp = System.getProperty("java.version");

            jreVersion = new JavaVersion(jreVersionProp);
        }

        return jreVersion;
    }

    /**
     * Compares version of the current JRE with the passed version.
     *
     * @param javaVersion Java version to compare to.
     * @return True, if current JRE is same version or higher.
     */
    public boolean isAtLeast(JavaVersion javaVersion) {
        return compareTo(javaVersion) >= 0;
    }

    /**
     * Compares version of the current JRE with the passed version.
     *
     * @param javaVersion Java version to compare to.
     * @return True, if current JRE is lower version.
     */
    public boolean isBelow(JavaVersion javaVersion) {
        return compareTo(javaVersion) < 0;
    }

    @Override
    public int compareTo(Object object) {
        JavaVersion cmpJavaVersion = (JavaVersion) object;

        if (major > cmpJavaVersion.getMajor()) {
            return 1;
        } else if (major < cmpJavaVersion.getMajor()) {
            return -1;
        }

        if (minor > cmpJavaVersion.getMinor()) {
            return 1;
        } else if (minor < cmpJavaVersion.getMinor()) {
            return -1;
        }

        if (security > cmpJavaVersion.getSecurity()) {
            return 1;
        } else if (security < cmpJavaVersion.getSecurity()) {
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
        result = 53 * result + minor;
        result = 53 * result + security;

        return result;
    }

    @Override
    public String toString() {
        return javaVersion;
    }
}
