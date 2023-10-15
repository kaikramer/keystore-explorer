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

package org.kse.utilities;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class SerialNumbersTest {

    @ParameterizedTest
    @ValueSource(ints = { 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 })
    void generate(int length) {
        BigInteger result = SerialNumbers.generate(length);

        assertThat(result.toByteArray().length).isEqualTo(length);
        assertThat(result).isPositive();
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 2, 3, 4, 5, 6, 7, 21, 22, 100 })
    void generateWrongLength(int length) {
        assertThatThrownBy(() -> SerialNumbers.generate(length)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @CsvSource({
            "0, 0",
            "0x00, 0",
            "1, 1",
            "01, 1",
            "0x01, 1",
            "a0, 160",
            "ff, 255",
            "0abc, 2748",
            "0x0abc, 2748",
            "abc, 2748",
            "0xabc, 2748",
            "1234567890, 1234567890",
            "0x1234567890, 78187493520",
    })
    void parse(String sn, BigInteger expectedResult) {
        assertThat(SerialNumbers.parse(sn)).isEqualTo(expectedResult);
    }
}