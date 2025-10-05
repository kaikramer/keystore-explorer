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

package org.kse.gui.table;

import java.util.ResourceBundle;

import javax.swing.table.AbstractTableModel;

/**
 * This abstract class provides a default implementation for column header tool tips. This table
 * model holds a reference the resource bundle and tool tip resource strings.
 */
public abstract class ToolTipTableModel extends AbstractTableModel {
    private static final long serialVersionUID = 1L;

    private ResourceBundle res;

    private String[] tooltips;

    /**
     * Constructs a ToolTipTableModel for use with ToolTipTable.
     *
     * @param res The resource bundle for the tool tip translations.
     * @param tooltips A String[] of the tool tip resource bundle strings. The array must have one
     *            entry for every column. If a column does not have a tool tip, leave the array
     *            index null.
     */
    public ToolTipTableModel(ResourceBundle res, String[] tooltips) {
        this.res = res;
        this.tooltips = tooltips;
    }

    /**
     *
     * @param col The column index.
     * @return The translated tool tip or null if the tool tip resource string is null.
     */
    public String getToolTip(int col) {
        return tooltips[col] != null ? res.getString(tooltips[col]) : null;
    }
}
