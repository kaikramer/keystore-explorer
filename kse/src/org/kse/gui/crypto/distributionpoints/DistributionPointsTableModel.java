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

package org.kse.gui.crypto.distributionpoints;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.table.AbstractTableModel;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * The table model used to display general names.
 */
public class DistributionPointsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 4224864830348756671L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/distributionpoints/resources");

    private String columnName;
    private List<DistributionPoint> data;

    /**
     * Construct a new DistributionPointsTableModel.
     */
    public DistributionPointsTableModel() {
        columnName = res.getString("DistributionPointsTableModel.DistributionPointColumn");

        data = new ArrayList<>();
    }

    public void load(CRLDistPoint cRLDistPoint) {
        DistributionPoint[] distributionPointArray = cRLDistPoint.getDistributionPoints();
        data = new ArrayList<>(Arrays.asList(distributionPointArray));
        data.sort(new DistributionPointComparator());
        fireTableDataChanged();
    }

    /**
     * Get the number of columns in the table.
     *
     * @return The number of columns
     */
    @Override
    public int getColumnCount() {
        return 1;
    }

    /**
     * Get the number of rows in the table.
     *
     * @return The number of rows
     */
    @Override
    public int getRowCount() {
        return data.size();
    }

    /**
     * Get the name of the column at the given position.
     *
     * @param col The column position
     * @return The column name
     */
    @Override
    public String getColumnName(int col) {
        return columnName;
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
        return data.get(row);
    }

    /**
     * Get the class at of the cells at the given column position.
     *
     * @param col The column position
     * @return The column cells' class
     */
    @Override
    public Class<?> getColumnClass(int col) {
        return GeneralName.class;
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
     * Add a row
     */
    public void addRow(DistributionPoint distributionPoint) {
        data.add(distributionPoint);
        data.sort(new DistributionPointComparator());
        fireTableDataChanged();
    }

    /**
     * Remove a row
     *
     * @param row Row number
     */
    public void removeRow(int row) {
        data.remove(row);
        fireTableDataChanged();
    }

    /**
     * Returns the table data
     *
     * @return List of general names as table data
     */
    public List<DistributionPoint> getData() {
        return data;
    }

    static class DistributionPointComparator implements Comparator<DistributionPoint> {
        @Override
        public int compare(DistributionPoint arg0, DistributionPoint arg1) {
            return 0;//fix
        }
    }
}
