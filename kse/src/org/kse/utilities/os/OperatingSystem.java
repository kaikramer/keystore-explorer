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
package org.kse.utilities.os;

/**
 * Local operating system detection.
 *
 */
public class OperatingSystem {
	private static final String osName = System.getProperty("os.name");
	private static final String osVersion = System.getProperty("os.version");

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
	 * Is operating system Windows NT 4?
	 *
	 * @return True if it is
	 */
	public static boolean isWindowsNt4() {
		return osName.indexOf("Windows NT") > -1 && osVersion.equals("4.0");
	}

	/**
	 * Is operating system Windows 95?
	 *
	 * @return True if it is
	 */
	public static boolean isWindows95() {
		return osName.indexOf("Windows 95") > -1 && osVersion.equals("4.0");
	}

	/**
	 * Is operating system Windows 98?
	 *
	 * @return True if it is
	 */
	public static boolean isWindows98() {
		return osName.indexOf("Windows") > -1 && osVersion.equals("4.1");
	}

	/**
	 * Is operating system Windows ME?
	 *
	 * @return True if it is
	 */
	public static boolean isWindowsMe() {
		return osName.indexOf("Windows") > -1 && osVersion.equals("4.9");
	}

	/**
	 * Is operating system Windows 2000?
	 *
	 * @return True if it is
	 */
	public static boolean isWindows2000() {
		return osName.indexOf("Windows") > -1 && osVersion.equals("5.0");
	}

	/**
	 * Is operating system Windows XP?
	 *
	 * @return True if it is
	 */
	public static boolean isWindowsXp() {
		return osName.indexOf("Windows") > -1 && osVersion.equals("5.1");
	}

	/**
	 * Is operating system Windows Vista?
	 *
	 * @return True if it is
	 */
	public static boolean isWindowsVista() {
		return osName.indexOf("Windows") > -1 && osVersion.equals("6.0");
	}

	/**
	 * Is operating system Windows 7?
	 *
	 * @return True if it is
	 */
	public static boolean isWindows7() {
		return osName.indexOf("Windows") > -1 && osVersion.equals("6.1");
	}

	/**
	 * Is operating system Windows 8 or 8.1?
	 *
	 * @return True if it is
	 */
	public static boolean isWindows8() {
		return osName.indexOf("Windows") > -1 && (osVersion.equals("6.2") || osVersion.equals("6.3"));
	}

	/**
	 * Is operating system Windows 10?
	 *
	 * @return True if it is
	 */
	public static boolean isWindows10() {
		return osName.indexOf("Windows") > -1 && osVersion.equals("10.0");
	}

	/**
	 * Is operating system one of the various Windows flavors?
	 *
	 * @return True if it is
	 */
	public static boolean isWindows() {
		return osName.indexOf("Windows") > -1;
	}

	/**
	 * Is operating system Linux?
	 *
	 * @return True if it is
	 */
	public static boolean isLinux() {
		return osName.indexOf("Linux") > -1;
	}

	/**
	 * Is operating system Mac OS?
	 *
	 * @return True if it is
	 */
	public static boolean isMacOs() {
		return osName.indexOf("Mac OS") > -1;
	}

	/**
	 * Is operating system Solaris?
	 *
	 * @return True if it is
	 */
	public static boolean isSolaris() {
		return osName.indexOf("Solaris") > -1 || osName.indexOf("SunOS") > -1;
	}

	/**
	 * Is operating system AIX?
	 *
	 * @return True if it is
	 */
	public static boolean isAix() {
		return osName.indexOf("AIX") > -1;
	}

	/**
	 * Is operating system FreeBSD?
	 *
	 * @return True if it is
	 */
	public static boolean isFreeBsd() {
		return osName.indexOf("FreeBSD") > -1;
	}

	/**
	 * Is operating system HP-UX?
	 *
	 * @return True if it is
	 */
	public static boolean isHpUx() {
		return osName.indexOf("HP-UX") > -1;
	}

	/**
	 * Is operating system Irix?
	 *
	 * @return True if it is
	 */
	public static boolean isIrix() {
		return osName.indexOf("Irix") > -1;
	}

	/**
	 * Is operating system Digital UNIX?
	 *
	 * @return True if it is
	 */
	public static boolean isDigitalUnix() {
		return osName.indexOf("Digital Unix") > -1;
	}

	/**
	 * Is operating system one of the various Unix flavors?
	 *
	 * @return True if it is
	 */
	public static boolean isUnix() {
		return isSolaris() || isAix() || isFreeBsd() || isHpUx() || isIrix() || isDigitalUnix();
	}

	/**
	 * Is operating system OS/2?
	 *
	 * @return True if it is
	 */
	public static boolean isOs2() {
		return osName.indexOf("OS/2") > -1;
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
