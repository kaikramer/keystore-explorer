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
package org.kse.gui.crypto.generalsubtree;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.table.AbstractTableModel;

import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.kse.crypto.x509.GeneralNameUtil;
import org.kse.crypto.x509.GeneralSubtrees;

/**
 * The table model used to display general subtrees.
 *
 */
public class GeneralSubtreesTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/generalsubtree/resources");

	private String[] columnNames;
	private Object[][] data;

	/**
	 * Construct a new GeneralSubtreesTableModel.
	 */
	public GeneralSubtreesTableModel() {
		columnNames = new String[3];
		columnNames[0] = res.getString("GeneralSubtreesTableModel.BaseColumn");
		columnNames[1] = res.getString("GeneralSubtreesTableModel.MinimumColumn");
		columnNames[2] = res.getString("GeneralSubtreesTableModel.MaximumColumn");

		data = new Object[0][0];
	}

	/**
	 * Load the GeneralSubtreesTableModel with general subtrees.
	 *
	 * @param generalSubtrees
	 *            The general subtrees
	 */
	public void load(GeneralSubtrees generalSubtrees) {
		List<GeneralSubtree> generalSubtreesList = generalSubtrees.getGeneralSubtrees();
		Collections.sort(generalSubtreesList, new GeneralSubtreeBaseComparator());

		data = new Object[generalSubtreesList.size()][3];

		int i = 0;
		for (GeneralSubtree generalSubtree : generalSubtreesList) {
			data[i][0] = generalSubtree;
			data[i][1] = generalSubtree;
			data[i][2] = generalSubtree;
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
		return GeneralSubtree.class;
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

	static class GeneralSubtreeBaseComparator implements Comparator<GeneralSubtree> {
		@Override
		public int compare(GeneralSubtree subtree1, GeneralSubtree subtree2) {
			return GeneralNameUtil.safeToString(subtree1.getBase(), false).compareToIgnoreCase(
					GeneralNameUtil.safeToString(subtree2.getBase(), false));
		}
	}

	static class GeneralSubtreeMinimumComparator implements Comparator<GeneralSubtree> {
		@Override
		public int compare(GeneralSubtree subtree1, GeneralSubtree subtree2) {
			return subtree1.getMinimum().compareTo(subtree2.getMinimum());
		}
	}

	static class GeneralSubtreeMaximumComparator implements Comparator<GeneralSubtree> {
		@Override
		public int compare(GeneralSubtree subtree1, GeneralSubtree subtree2) {
			// Maximum may be null;
			BigInteger maximum1 = BigInteger.valueOf(-1);
			BigInteger maximum2 = BigInteger.valueOf(-1);

			if (subtree1.getMaximum() != null) {
				maximum1 = subtree1.getMaximum();
			}

			if (subtree2.getMaximum() != null) {
				maximum2 = subtree2.getMaximum();
			}

			return maximum1.compareTo(maximum2);
		}
	}
}
