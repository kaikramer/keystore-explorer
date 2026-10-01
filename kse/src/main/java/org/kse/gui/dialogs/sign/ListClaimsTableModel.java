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

package org.kse.gui.dialogs.sign;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ResourceBundle;

import org.kse.gui.table.LoadableTableModel;
import org.kse.gui.table.ToolTipTableModel;

/**
 * The table model used to display a list of custom claims
 */
public class ListClaimsTableModel extends ToolTipTableModel implements LoadableTableModel<CustomClaim> {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

    private static final String[] COLUMN_TOOL_TIPS = { //
            "ListClaimsTableModel.NameColumn.tooltip", //
            "ListClaimsTableModel.ValueColumn.tooltip" //
    };

    private String[] columnNames;
    List<CustomClaim> listClaims;

    /**
     * Construct a new ListClaimsTableModel.
     */
    public ListClaimsTableModel() {
        super(res, COLUMN_TOOL_TIPS);
        columnNames = new String[2];
        columnNames[0] = res.getString("ListClaimsTableModel.NameColumn");
        columnNames[1] = res.getString("ListClaimsTableModel.ValueColumn");

        listClaims = new ArrayList<>();
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
        return listClaims.size();
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
        return listClaims.get(row);
    }

    /**
     * Get the class at of the cells at the given column position.
     *
     * @param col The column position
     * @return The column cells' class
     */
    @Override
    public Class<?> getColumnClass(int col) {
        return CustomClaim.class;
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

    @Override
    public void load(List<CustomClaim> listClaims) {
        this.listClaims = listClaims;
        this.listClaims.sort(new CustomClaimNameComparator());

        fireTableDataChanged();
    }

    static class CustomClaimNameComparator implements Comparator<CustomClaim> {
        @Override
        public int compare(CustomClaim o1, CustomClaim o2) {
            return o1.getName().compareToIgnoreCase(o2.getName());
        }
    }

    static class CustomClaimValueComparator implements Comparator<CustomClaim> {
        @Override
        public int compare(CustomClaim o1, CustomClaim o2) {
            return o1.getValue().compareToIgnoreCase(o2.getValue());
        }
    }
}
