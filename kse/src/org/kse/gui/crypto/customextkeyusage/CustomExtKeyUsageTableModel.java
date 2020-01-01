/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
package org.kse.gui.crypto.customextkeyusage;

import java.util.Arrays;
import java.util.Comparator;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.table.AbstractTableModel;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * The table model used to display Custom Extended Key Usage oids.
 *
 */
public class CustomExtKeyUsageTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/customextkeyusage/resources");

	private String[] columnNames;
	private Object[][] data;

	/**
	 * Construct a new CustomExtKeyUsageTableModel.
	 */
	public CustomExtKeyUsageTableModel() {
		columnNames = new String[1];
		columnNames[0] = res.getString("CustomExtKeyUsageTableTableModel.ObjectId");
		data = new Object[0][0];
	}

	/**
	 * Load the CustomExtKeyUsageTableModel with EKU oids.
	 *
	 * @param CustomExtKeyUsage
	 *            The EKU oids
	 */
	public void load(Set<ASN1ObjectIdentifier> objectIds) {
		ASN1ObjectIdentifier[] objectIdsArray = objectIds
				.toArray(new ASN1ObjectIdentifier[objectIds.size()]);
		Arrays.sort(objectIdsArray, Comparator.comparing(ASN1ObjectIdentifier::getId,
				Comparator.nullsFirst(String.CASE_INSENSITIVE_ORDER)));

		data = new Object[objectIdsArray.length][2];

		int i = 0;
		for (ASN1ObjectIdentifier CustomExtKeyUsage : objectIdsArray) {
			data[i][0] = CustomExtKeyUsage;
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
		return ASN1ObjectIdentifier.class;
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
