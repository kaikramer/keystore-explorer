/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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
package org.kse.utilities.os;

/**
 * Local operating system detection.
 */
public class OperatingSystem {
    private static final String OS_NAME = System.getProperty("os.name");
    private static final String OS_VERSION = System.getProperty("os.version");

    // @formatter:off
    /*
     * OS detection is relatively simple for most platforms. Simply check that
     * the 'os.name' system property contains a recognized string. Windows is
     * the exception as the os name may be wrong, e.g. Windows 2000 is sometimes
     * reported as 'Windows NT' We therefore check for the string 'Windows' only
     * and use the 'os.version' system property to discriminate:
     *
     * - NT4 : 4.0 - 95 : 4.0 - 98 : 4.1 - ME : 4.9 - 2000 : 5.0 - XP : 5.1 -
     * Vista : 6.0 - 7: 6.1 - 8: 6.2 - 8.1: 6.3 - 10: 10.0
     *
     * This works find except for NT4 and 95 which have the same version. For
     * these we also check for the full os name as well.
     */
    // @formatter:on

    private OperatingSystem() {
    }

    /**
     * Is operating system Windows 10?
     *
     * @return True if it is
     */
    public static boolean isWindows10() {
        return OS_NAME.contains("Windows") && OS_VERSION.equals("10.0");
    }

    /**
     * Is operating system one of the various Windows flavors?
     *
     * @return True if it is
     */
    public static boolean isWindows() {
        return OS_NAME.contains("Windows");
    }

    /**
     * Is operating system Linux?
     *
     * @return True if it is
     */
    public static boolean isLinux() {
        return OS_NAME.contains("Linux");
    }

    /**
     * Is operating system macOS?
     *
     * @return True if it is
     */
    public static boolean isMacOs() {
        return OS_NAME.contains("Mac OS");
    }

    /**
     * Is operating system Solaris?
     *
     * @return True if it is
     */
    public static boolean isSolaris() {
        return OS_NAME.contains("Solaris") || OS_NAME.contains("SunOS");
    }

    /**
     * Is operating system AIX?
     *
     * @return True if it is
     */
    public static boolean isAix() {
        return OS_NAME.contains("AIX");
    }

    /**
     * Is operating system FreeBSD?
     *
     * @return True if it is
     */
    public static boolean isFreeBsd() {
        return OS_NAME.contains("FreeBSD");
    }

    /**
     * Is operating system HP-UX?
     *
     * @return True if it is
     */
    public static boolean isHpUx() {
        return OS_NAME.contains("HP-UX");
    }

    /**
     * Is operating system one of the various Unix flavors?
     *
     * @return True if it is
     */
    public static boolean isUnix() {
        return isSolaris() || isAix() || isFreeBsd() || isHpUx();
    }

    /**
     * Is operating system OS/2?
     *
     * @return True if it is
     */
    public static boolean isOs2() {
        return OS_NAME.contains("OS/2");
    }

    /**
     * Is operating system unknown?
     *
     * @return True if it is
     */
    public static boolean isUnknown() {
        return !isWindows() && !isLinux() && !isMacOs() && !isUnix() && !isOs2();
    }
}
