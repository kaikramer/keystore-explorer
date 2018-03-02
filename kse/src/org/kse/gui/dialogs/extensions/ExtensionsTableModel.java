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
package org.kse.gui.dialogs.extensions;

import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.table.AbstractTableModel;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.crypto.x509.X509Ext;

/**
 * The table model used to display X.509 extensions.
 *
 */
public class ExtensionsTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private String[] columnNames;
	private Object[][] data;

	/**
	 * Construct a new ExtensionsTableModel.
	 */
	public ExtensionsTableModel() {
		columnNames = new String[3];
		columnNames[0] = res.getString("ExtensionsTableModel.CriticalColumn");
		columnNames[1] = res.getString("ExtensionsTableModel.NameColumn");
		columnNames[2] = res.getString("ExtensionsTableModel.OidColumn");

		data = new Object[0][0];
	}

	/**
	 * Load the ExtensionsTableModel with X.509 extensions.
	 *
	 * @param extensions
	 *            The X.509 extensions
	 */
	public void load(X509Extension extensions) {
		Set<String> critExts = extensions.getCriticalExtensionOIDs();
		Set<String> nonCritExts = extensions.getNonCriticalExtensionOIDs();

		// Rows will be sorted by extension name
		List<X509Ext> sortedExts = new ArrayList<X509Ext>();

		for (Iterator<String> itr = critExts.iterator(); itr.hasNext();) {
			String extOid = itr.next();
			byte[] value = extensions.getExtensionValue(extOid);

			X509Ext ext = new X509Ext(new ASN1ObjectIdentifier(extOid), value, true);

			sortedExts.add(ext);
		}

		for (Iterator<String> itr = nonCritExts.iterator(); itr.hasNext();) {
			String extOid = itr.next();
			byte[] value = extensions.getExtensionValue(extOid);

			X509Ext ext = new X509Ext(new ASN1ObjectIdentifier(extOid), value, false);

			sortedExts.add(ext);
		}

		Collections.sort(sortedExts, new ExtensionNameComparator());

		data = new Object[sortedExts.size()][3];

		int i = 0;
		for (Iterator<X509Ext> itrSortedExts = sortedExts.iterator(); itrSortedExts.hasNext();) {
			X509Ext ext = itrSortedExts.next();
			loadRow(ext, i);
			i++;
		}

		fireTableDataChanged();
	}

	private void loadRow(X509Ext extension, int row) {
		data[row][0] = Boolean.valueOf(extension.isCriticalExtension());

		String name = extension.getName();

		if (name == null) {
			data[row][1] = "";
		} else {
			data[row][1] = name;
		}

		data[row][2] = extension.getOid();
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
			return Boolean.class;
		case 1:
			return String.class;
		default:
			return ASN1ObjectIdentifier.class;
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

	private class ExtensionNameComparator implements Comparator<X509Ext> {
		@Override
		public int compare(X509Ext ext1, X509Ext ext2) {

			// compare extension names
			String name1 = ext1.getName();
			String name2 = ext2.getName();

			if (name1 == null) {
				name1 = "-";
			}

			if (name2 == null) {
				name2 = "-";
			}

			int result = name1.compareToIgnoreCase(name2);

			// compare extension OIDs if names are equal
			if (result == 0) {
				result = ext1.getOid().getId().compareToIgnoreCase(ext2.getOid().getId());
			}

			return result;
		}
	}
}
