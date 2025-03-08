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
package org.kse.utilities.oid;

import static org.assertj.core.api.Assertions.assertThat;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ObjectIdComparatorTest {

    @ParameterizedTest
    @CsvSource({
            "2.5.4.3,       2.5.4.3,     0",
            "2.5.4.3,       2.5.4.4,    -1",
            "2.5.4.4,       2.5.4.3,     1",
            "2.5.4.3,       2.5.4.3.1,  -1",
            "2.5.4.3.1,     2.5.4.3,     1",
            "2.5.4.3,       2.5.4.3.0,   0",
            "2.5.4.3,       2.5.4.3.0.0, 0",
            "2.5.4.3.0,     2.5.4.3,     0",
            "2.5.4.3.0.0,   2.5.4.3,     0",
            "2.25.178307330326388478625988293987992454427, 2.25.178307330326388478625988293987992454427,  0",
            "2.25.178307330326388478625988293987992454427, 2.25.178307330326388478625988293987992454428, -1",
            "2.25.178307330326388478625988293987992454428, 2.25.178307330326388478625988293987992454427,  1",
    })
    void compare(String oid1, String oid2, int expected) {
        ObjectIdComparator comparator = new ObjectIdComparator();

        ASN1ObjectIdentifier asn1Oid1 = new ASN1ObjectIdentifier(oid1);
        ASN1ObjectIdentifier asn1Oid2 = new ASN1ObjectIdentifier(oid2);

        assertThat(comparator.compare(asn1Oid1, asn1Oid2)).isEqualTo(expected);
    }
}