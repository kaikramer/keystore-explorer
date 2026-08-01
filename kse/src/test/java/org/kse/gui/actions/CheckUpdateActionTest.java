/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

package org.kse.gui.actions;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class CheckUpdateActionTest {

    @ParameterizedTest
    @CsvSource({
            "2026-07-01, 2026-07-14, 14, false",
            "2026-07-01, 2026-07-15, 14, true",
            "2026-07-01, 2026-08-01, 14, true",
    })
    void isCheckDue(String lastCheck, String now, int interval, boolean expected) {
        assertThat(CheckUpdateAction.isCheckDue(LocalDate.parse(lastCheck), LocalDate.parse(now), interval))
                .isEqualTo(expected);
    }
}
