/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class VersionTest {

    @ParameterizedTest
    // @formatter:off
    @CsvSource({
            "5",
            "5.0",
            "5.0.0",
            "5.2.2",
            "5.3",
            "5.2.2\n", // has to be last in list because of the the additional new line
    })
    // @formatter:on
    public void testVersionString(String verString) {
        new Version(verString);
    }

    @ParameterizedTest
    // @formatter:off
    @CsvSource({
            "''",
            "a",
            "ea",
            "1-0-0",
    })
    // @formatter:on
    public void invalidVersion(String verString) {
        assertThrows(VersionException.class, () -> new Version(verString));
    }

    @ParameterizedTest
    // @formatter:off
    @CsvSource({
            "01, 		1, 0, 0",
            "1, 		1, 0, 0",
            "1.0, 		1, 0, 0",
            "1.0.0,		1, 0, 0",
            "1.2, 		1, 2, 0",
            "1.2.3, 	1, 2, 3",
            "1.2.3, 	1, 2, 3",
            "1.2.3.4, 	1, 2, 3",
    })
    // @formatter:on
    public void testMajorMinorVersion(String versionString, int major, int minor, int bugfix) {
        assertEquals(major, new Version(versionString).getMajor());
        assertEquals(minor, new Version(versionString).getMinor());
        assertEquals(bugfix, new Version(versionString).getBugfix());
    }

    @ParameterizedTest
    // @formatter:off
    @CsvSource({
            "01, 		1, 		0",
            "1, 		1, 		0",
            "1.0, 		1, 		0",
            "1.0.0,		1, 		0",
            "1.0, 		1.0, 	0",
            "1.0.0,		1.0.0, 	0",
            "1.2, 		1, 		1",
            "1.2, 		1.3, 	-1",
            "1.2.3, 	1, 		1",
            "1.2.3.4, 	1, 		1",
            "1.3.1, 	1.3,	1",
            "1.2.3, 	1.3,	-1",
            "1.2.3.4, 	1.3, 	-1",
            "1.3.1, 	1.3.2, 	-1",
            "1.3.2, 	1.3.2.1,-1",
            "9.9.9.9,	10.0.0, -1",
            "9.20.20,	10.0.0, -1",
    })
    // @formatter:on
    public void testCompare(String version1, String version2, int resultSignum) {
        assertEquals(Integer.signum(new Version(version1).compareTo(new Version(version2))), resultSignum);
    }
}