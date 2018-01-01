/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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

import java.math.BigInteger;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.swing.table.AbstractTableModel;

/**
 * The table model used to display an array of X.509 CRL entries sorted by
 * serial number.
 *
 */
public class RevokedCertsTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private String[] columnNames;
	private Object[][] data;

	/**
	 * Construct a new RevokedCertsTableModel.
	 */
	public RevokedCertsTableModel() {
		columnNames = new String[2];
		columnNames[0] = res.getString("RevokedCertsTableModel.SerialNumberColumn");
		columnNames[1] = res.getString("RevokedCertsTableModel.RevocationDateColumn");

		data = new Object[0][0];
	}

	/**
	 * Load the RevokedCertsTableModel with an array of X.509 CRL entries.
	 *
	 * @param revokedCerts
	 *            The X.509 CRL entries
	 */
	public void load(X509CRLEntry[] revokedCerts) {
		TreeMap<BigInteger, X509CRLEntry> sortedRevokedCerts = new TreeMap<BigInteger, X509CRLEntry>();

		for (int i = 0; i < revokedCerts.length; i++) {
			sortedRevokedCerts.put(revokedCerts[i].getSerialNumber(), revokedCerts[i]);
		}

		data = new Object[sortedRevokedCerts.size()][2];

		int i = 0;
		for (Iterator<?> itr = sortedRevokedCerts.entrySet().iterator(); itr.hasNext(); i++) {
			X509CRLEntry x509CrlEntry = (X509CRLEntry) ((Map.Entry) itr.next()).getValue();

			data[i][0] = x509CrlEntry.getSerialNumber();
			data[i][1] = x509CrlEntry.getRevocationDate();
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
	 * @param col
	 *            The column position
	 * @return The column name
	 */
	@Override
	public String getColumnName(int col) {
		return columnNames[col];
	}

	/**
	 * Get the cell value at the given row and column position.
	 *
	 * @param row
	 *            The row position
	 * @param col
	 *            The column position
	 * @return The cell value
	 */
	@Override
	public Object getValueAt(int row, int col) {
		return data[row][col];
	}

	/**
	 * Get the class at of the cells at the given column position.
	 *
	 * @param col
	 *            The column position
	 * @return The column cells' class
	 */
	@Override
	public Class<?> getColumnClass(int col) {
		switch (col) {
		case 0:
			return BigInteger.class;
		default:
			return Date.class;
		}
	}

	/**
	 * Is the cell at the given row and column position editable?
	 *
	 * @param row
	 *            The row position
	 * @param col
	 *            The column position
	 * @return True if the cell is editable, false otherwise
	 */
	@Override
	public boolean isCellEditable(int row, int col) {
		return false;
	}
}
