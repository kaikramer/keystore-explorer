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
package org.kse.gui.jar;

import java.io.File;
import java.io.IOException;
import java.util.ResourceBundle;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import javax.swing.table.AbstractTableModel;

/**
 * The table model used to display information about JAR files.
 *
 */
public class JarInfoTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/jar/resources");

	private String[] columnNames;
	private Object[][] data;

	/**
	 * Construct a new JarInfoTableModel.
	 */
	public JarInfoTableModel() {
		columnNames = new String[8];
		columnNames[0] = res.getString("JarInfoTableModel.JarFileColumn");
		columnNames[1] = res.getString("JarInfoTableModel.SizeColumn");
		columnNames[2] = res.getString("JarInfoTableModel.SpecificationTitleColumn");
		columnNames[3] = res.getString("JarInfoTableModel.SpecificationVersionColumn");
		columnNames[4] = res.getString("JarInfoTableModel.SpecificationVendorColumn");
		columnNames[5] = res.getString("JarInfoTableModel.ImplementationTitleColumn");
		columnNames[6] = res.getString("JarInfoTableModel.ImplementationVersionColumn");
		columnNames[7] = res.getString("JarInfoTableModel.ImplementationVendorColumn");

		data = new Object[0][0];
	}

	/**
	 * Load the JarInfoTableModel with an array of JAR files.
	 *
	 * @param jarFiles
	 *            The JAR files
	 * @throws IOException
	 *             Problem occurred getting JAR information
	 */
	public void load(JarFile[] jarFiles) throws IOException {
		data = new Object[jarFiles.length][8];

		for (int i = 0; i < jarFiles.length; i++) {
			JarFile jarFile = jarFiles[i];
			String fileName = jarFile.getName();
			File file = new File(fileName);

			Manifest manifest = jarFile.getManifest();

			String implementationTitle = "";
			String implementationVersion = "";
			String implementationVendor = "";
			String specificationTitle = "";
			String specificationVersion = "";
			String specificationVendor = "";

			if (manifest != null) {
				Attributes attributes = manifest.getMainAttributes();

				String value = attributes.getValue("Specification-Title");
				if (value != null) {
					specificationTitle = value;
				}

				value = attributes.getValue("Specification-Version");
				if (value != null) {
					specificationVersion = value;
				}

				value = attributes.getValue("Specification-Vendor");
				if (value != null) {
					specificationVendor = value;
				}

				value = attributes.getValue("Implementation-Title");
				if (value != null) {
					implementationTitle = value;
				}

				value = attributes.getValue("Implementation-Version");
				if (value != null) {
					implementationVersion = value;
				}

				value = attributes.getValue("Implementation-Vendor");
				if (value != null) {
					implementationVendor = value;
				}
			}

			data[i][0] = file.getName();
			data[i][1] = Math.round(file.length() / 1024);
			data[i][2] = specificationTitle;
			data[i][3] = specificationVersion;
			data[i][4] = specificationVendor;
			data[i][5] = implementationTitle;
			data[i][6] = implementationVersion;
			data[i][7] = implementationVendor;
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
			return String.class;
		case 1:
			return Long.class;
		case 2:
			return String.class;
		case 3:
			return String.class;
		case 4:
			return String.class;
		case 5:
			return String.class;
		case 6:
			return String.class;
		default:
			return String.class;
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
