/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2015 Kai Kramer
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
package net.sf.keystore_explorer.gui.crypto.generalname;

import java.util.Arrays;
import java.util.Comparator;
import java.util.ResourceBundle;

import javax.swing.table.AbstractTableModel;

import net.sf.keystore_explorer.crypto.x509.GeneralNameUtil;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * The table model used to display general names.
 * 
 */
public class GeneralNamesTableModel extends AbstractTableModel {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/crypto/generalname/resources");

	private String[] columnNames;
	private Object[][] data;

	/**
	 * Construct a new GeneralNamesTableModel.
	 */
	public GeneralNamesTableModel() {
		columnNames = new String[1];
		columnNames[0] = res.getString("GeneralNamesTableModel.GeneralNameColumn");

		data = new Object[0][0];
	}

	/**
	 * Load the GeneralNamesTableModel with general names.
	 * 
	 * @param generalNames
	 *            The general names
	 */
	public void load(GeneralNames generalNames) {
		GeneralName[] generalNamesArray = generalNames.getNames();
		Arrays.sort(generalNamesArray, new GeneralNameComparator());

		data = new Object[generalNamesArray.length][1];

		int i = 0;
		for (GeneralName generalName : generalNamesArray) {
			data[i][0] = generalName;
			i++;
		}

		fireTableDataChanged();
	}

	/**
	 * Get the number of columns in the table.
	 * 
	 * @return The number of columns
	 */
	public int getColumnCount() {
		return columnNames.length;
	}

	/**
	 * Get the number of rows in the table.
	 * 
	 * @return The number of rows
	 */
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
	public Class<?> getColumnClass(int col) {
		return GeneralName.class;
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
	public boolean isCellEditable(int row, int col) {
		return false;
	}

	static class GeneralNameComparator implements Comparator<GeneralName> {
		public int compare(GeneralName name1, GeneralName name2) {
			return GeneralNameUtil.safeToString(name1).compareToIgnoreCase(GeneralNameUtil.safeToString(name2));
		}
	}
}
