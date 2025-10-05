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

package org.kse.gui.dialogs;

import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import org.kse.crypto.signing.KseJarEntry;
import org.kse.gui.table.ToolTipTableModel;

/**
 * The table model used to display an array of signed JAR entries.
 */
public class SignedJarTableModel extends ToolTipTableModel {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final String[] COLUMN_TOOL_TIPS = { //
            "SignedJarTableModel.FlagsColumn.tooltip", //
            "SignedJarTableModel.SizeColumn.tooltip", //
            "SignedJarTableModel.DateColumn.tooltip", //
            "SignedJarTableModel.NameColumn.tooltip" //
    };

    static final int COL_FLAGS = 0;
    static final int COL_SIZE = 1;
    static final int COL_DATE = 2;
    static final int COL_NAME = 3;
    private static final int COLUMN_COUNT = 4;

    private int[] columnSizes = {50, 50, 200, 400};
    private String[] columnNames;
    private Object[][] data;

    /**
     * Construct a new SignedJarTableModel.
     */
    public SignedJarTableModel() {
        super(res, COLUMN_TOOL_TIPS);
        columnNames = new String[COLUMN_COUNT];
        columnNames[COL_FLAGS] = res.getString("SignedJarTableModel.FlagsColumn.text");
        columnNames[COL_SIZE] = res.getString("SignedJarTableModel.SizeColumn.text");
        columnNames[COL_DATE] = res.getString("SignedJarTableModel.DateColumn.text");
        columnNames[COL_NAME] = res.getString("SignedJarTableModel.NameColumn.text");

        data = new Object[0][0];
    }

    /**
     * Load the SignedJarTableModel with a list of JAR entries.
     *
     * @param jarEntries The JAR entries
     */
    public void load(List<KseJarEntry> jarEntries) {

        data = new Object[jarEntries.size()][COLUMN_COUNT];

        int i = 0;
        for (KseJarEntry entry : jarEntries) {
            data[i][COL_FLAGS] = entry.getFlags();
            data[i][COL_SIZE] = entry.getSize();
            data[i][COL_DATE] = new Date(entry.getTime());
            data[i][COL_NAME] = entry.getName();
            ++i;
        }

        fireTableDataChanged();
    }

    /**
     * Get the number of columns in the table.
     *
     * @return The number of columns
     */
    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    /**
     * Get the number of rows in the table.
     *
     * @return The number of rows
     */
    @Override
    public int getRowCount() {
        return data.length;
    }

    /**
     * Get the name of the column at the given position.
     *
     * @param col The column position
     * @return The column name
     */
    @Override
    public String getColumnName(int col) {
        return columnNames[col];
    }

    /**
     * Get the cell value at the given row and column position.
     *
     * @param row The row position
     * @param col The column position
     * @return The cell value
     */
    @Override
    public Object getValueAt(int row, int col) {
        return data[row][col];
    }

    /**
     * Get the class at of the cells at the given column position.
     *
     * @param col The column position
     * @return The column cells' class
     */
    @Override
    public Class<?> getColumnClass(int col) {
        switch (col) {
            case COL_FLAGS:
                return String.class;
            case COL_SIZE:
                return Long.class;
            case COL_DATE:
                return Date.class;
            case COL_NAME:
                return String.class;
        }
        throw new IndexOutOfBoundsException(String.valueOf(col));
    }

    /**
     * Is the cell at the given row and column position editable?
     *
     * @param row The row position
     * @param col The column position
     * @return True if the cell is editable, false otherwise
     */
    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    /**
     *
     * @param col The column position
     * @return The size for the column
     */
    public int getColumnSize(int col) {
        return columnSizes[col];
    }
}
