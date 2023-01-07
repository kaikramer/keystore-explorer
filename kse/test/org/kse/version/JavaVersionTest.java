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

import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ArgumentConverter;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;

public class JavaVersionTest {

    @ParameterizedTest
    @CsvSource({
            "JRE_VERSION_160, 1.6.0",
            "JRE_VERSION_170, 1.7.0",
            "JRE_VERSION_180, 1.8.0",
            "JRE_VERSION_9, 9",
            "JRE_VERSION_9, 9.0.0",
            "JRE_VERSION_10, 10.0.0",
            "JRE_VERSION_11, 11.0.0",
    })
    public void equals(@ConvertWith(JavaVersionConstantArgumentConverter.class) JavaVersion verConst, String verStr) {
        assertEquals(verConst, new JavaVersion(verStr));
    }

    @ParameterizedTest
    @CsvSource({
            "JRE_VERSION_160, 1.6.0_45,  0",
            "JRE_VERSION_170, 1.6.0_45,  1",
            "JRE_VERSION_170, 1.7.0_101, 0",
            "JRE_VERSION_180, 1.7.0_101, 1",
            "JRE_VERSION_180, 1.8.0_20,  0",
            "JRE_VERSION_170, 1.8.0_20, -1",
            "JRE_VERSION_160, 1.8.0_20, -1",
            "JRE_VERSION_9,   1.8.0_20,  1",
            "JRE_VERSION_9,   9.0.0,     0",
            "JRE_VERSION_9,   9.0.1,    -1",
            "JRE_VERSION_9,   10.0.1,   -1",
            "JRE_VERSION_10,  9.0.1,     1",
            "JRE_VERSION_10,  10.0.0,    0",
            "JRE_VERSION_10,  10.0.1,   -1",
            "JRE_VERSION_10,  11.0.1,   -1",
            "JRE_VERSION_11,  10.0.1,    1",
            "JRE_VERSION_11,  11.0.0,    0",
            "JRE_VERSION_11,  11.0.1,   -1",
    })
    public void compareTo(@ConvertWith(JavaVersionConstantArgumentConverter.class) JavaVersion verConst, String verStr,
                          int result) {
        assertEquals(Integer.signum(verConst.compareTo(new JavaVersion(verStr))), result);
    }

    @ParameterizedTest
    @CsvSource({
            "1.8.0_20-b62, 	1, 8, 0",
            "9, 			9, 0, 0",
            "9-ea, 			9, 0, 0",
            "10.0.0, 	   10, 0, 0",
            "10.0.1, 	   10, 0, 1",
    })
    public void getMajorMinorSecurity(String ver, int major, int minor, int security) {
        assertEquals(major, new JavaVersion(ver).getMajor());
        assertEquals(minor, new JavaVersion(ver).getMinor());
        assertEquals(security, new JavaVersion(ver).getSecurity());
    }

    @ParameterizedTest
    @CsvSource({
            "JRE_VERSION_9,   JRE_VERSION_160, true",
            "JRE_VERSION_9,   JRE_VERSION_170, true",
            "JRE_VERSION_9,   JRE_VERSION_180, true",
            "JRE_VERSION_9,   JRE_VERSION_9,   true",
            "JRE_VERSION_10,  JRE_VERSION_160, true",
            "JRE_VERSION_10,  JRE_VERSION_170, true",
            "JRE_VERSION_10,  JRE_VERSION_180, true",
            "JRE_VERSION_10,  JRE_VERSION_9,   true",
            "JRE_VERSION_180, JRE_VERSION_160, true",
            "JRE_VERSION_180, JRE_VERSION_170, true",
            "JRE_VERSION_180, JRE_VERSION_180, true",
            "JRE_VERSION_170, JRE_VERSION_160, true",
            "JRE_VERSION_170, JRE_VERSION_170, true",
            "JRE_VERSION_180, JRE_VERSION_9,   false",
            "JRE_VERSION_170, JRE_VERSION_180, false",
            "JRE_VERSION_170, JRE_VERSION_9,   false",
            "JRE_VERSION_9,   JRE_VERSION_9,   true",
            "JRE_VERSION_10,  JRE_VERSION_9,   true",
            "JRE_VERSION_9,   JRE_VERSION_10,  false",
            "JRE_VERSION_10,  JRE_VERSION_9,   true",
            "JRE_VERSION_10,  JRE_VERSION_10,  true",
            "JRE_VERSION_10,  JRE_VERSION_11,  false",
    })
    public void isAtLeast(@ConvertWith(JavaVersionConstantArgumentConverter.class) JavaVersion version1,
                          @ConvertWith(JavaVersionConstantArgumentConverter.class) JavaVersion version2,
                          boolean result) {
        assertEquals(version1.isAtLeast(version2), result);
    }

    @ParameterizedTest
    @CsvSource({
            "JRE_VERSION_160, JRE_VERSION_170, true",
            "JRE_VERSION_170, JRE_VERSION_180, true",
            "JRE_VERSION_180, JRE_VERSION_9,   true",
            "JRE_VERSION_9,   JRE_VERSION_180, false",
            "JRE_VERSION_170, JRE_VERSION_160, false",
            "JRE_VERSION_170, JRE_VERSION_170, false",
            "JRE_VERSION_180, JRE_VERSION_160, false",
            "JRE_VERSION_180, JRE_VERSION_170, false",
            "JRE_VERSION_180, JRE_VERSION_180, false",
    })
    public void isBelow(@ConvertWith(JavaVersionConstantArgumentConverter.class) JavaVersion version1,
                        @ConvertWith(JavaVersionConstantArgumentConverter.class) JavaVersion version2, boolean result) {
        assertEquals(version1.isBelow(version2), result);
    }

    @ParameterizedTest
    @CsvSource({
            "a.b.c",
            "a.1.0",
            "X",
            "ea",
    })
    public void invalidVersion(String verString) {
        assertThrows(VersionException.class, () -> new JavaVersion(verString));
    }

    static class JavaVersionConstantArgumentConverter implements ArgumentConverter {
        @Override
        public Object convert(Object source, ParameterContext context) throws ArgumentConversionException {
            try {
                return JavaVersion.class.getField(String.valueOf(source)).get(null);
            } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
                throw new ArgumentConversionException(e.toString());
            }
        }
    }
}
