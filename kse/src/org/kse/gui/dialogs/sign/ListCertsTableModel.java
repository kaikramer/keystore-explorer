package org.kse.gui.dialogs.sign;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.table.AbstractTableModel;

public class ListCertsTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

	private String[] columnNames;
	private Object[][] data;

	public ListCertsTableModel() {
		columnNames = new String[3];
		columnNames[0] = res.getString("ListCertsTableModel.EntryNameColumn");
		columnNames[1] = res.getString("ListCertsTableModel.SerialNumberColumn");
		columnNames[2] = res.getString("ListCertsTableModel.CertificateExpiryColumn");

		data = new Object[0][0];
	}

	public void load(List<X509Certificate> listCertificados) {
		data = new Object[listCertificados.size()] [3];
		int i = 0;
		for (X509Certificate cert : listCertificados) {
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
		if (col == 0) {
			return BigInteger.class;
		} else {
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
