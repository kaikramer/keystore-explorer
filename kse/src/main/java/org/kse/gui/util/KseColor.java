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

package org.kse.gui.util;

import java.awt.Color;

/**
 * Enum defining colors for use in KSE. These colors match most color schemes used in KSE.
 * <p>
 * <a href="https://plugins.jetbrains.com/docs/intellij/icons-style.html#action-icons">source</a>
 */
public enum KseColor {
    BLUE("#389FD6"),
    GREEN("#59A869"),
    RED("#DB5860"),
    YELLOW("#EDA200"),
    GREY("#7F8B91");

    private final String hexCode;

    KseColor(String hexCode) {
        this.hexCode = hexCode;
    }

    public Color getColor() {
        return Color.decode(hexCode);
    }
}
