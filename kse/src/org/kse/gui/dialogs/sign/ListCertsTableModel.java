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

package org.kse.gui.dialogs.sign;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.table.AbstractTableModel;

/**
 * The table model used to display a list of X.509 certificates sorted by name
 * column
 */
public class ListCertsTableModel extends AbstractTableModel {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

    private String[] columnNames;
    private Object[][] data;

    /**
     * Construct a new ListCertsTableModel
     */
    public ListCertsTableModel() {
        columnNames = new String[3];
        columnNames[0] = res.getString("ListCertsTableModel.EntryNameColumn");
        columnNames[1] = res.getString("ListCertsTableModel.SerialNumberColumn");
        columnNames[2] = res.getString("ListCertsTableModel.CertificateExpiryColumn");

        data = new Object[0][0];
    }

    public void load(List<X509Certificate> listCertificates) {
        data = new Object[listCertificates.size()][3];
        int i = 0;
        for (X509Certificate cert : listCertificates) {
            data[i][0] = cert.getSubjectX500Principal().getName();
            data[i][1] = cert.getSerialNumber();
            data[i][2] = cert.getNotAfter();
            i++;
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
        if (col == 0) {
            return BigInteger.class;
        } else {
            return Date.class;
        }
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

}
