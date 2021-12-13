package org.kse.gui.dialogs.sign;

import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.table.AbstractTableModel;

public class ListClaimsTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

	private String[] columnNames;
	List<CustomClaim> listClaims;

	public ListClaimsTableModel() {
		columnNames = new String[2];
		columnNames[0] = res.getString("ListClaimsTableModel.NameColumn");
		columnNames[1] = res.getString("ListClaimsTableModel.ValueColumn");

		listClaims = new ArrayList<CustomClaim>();
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
		CustomClaim customClaim = listClaims.get(row);
		if (col == 0) {
			return customClaim.getName();
		} else {
			return customClaim.getValue();
		}
	}

	/**
	 * Get the class at of the cells at the given column position.
	 *
	 * @param col The column position
	 * @return The column cells' class
	 */
	@Override
	public Class<?> getColumnClass(int col) {
		return String.class;
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

	public void removeRow(int selectedRow) {
		listClaims.remove(selectedRow);
		fireTableDataChanged();
	}

	public void load(List<CustomClaim> listClaims) {
		this.listClaims.addAll(listClaims);
		fireTableDataChanged();
	}

	public void addRow(CustomClaim customClaim) {
		listClaims.add(customClaim);
		fireTableDataChanged();
	}

	public List<CustomClaim> getData() {
		return listClaims;
	}

	public void updateRow(int selectedRow, CustomClaim customClaim) {
		listClaims.set(selectedRow, customClaim);
		fireTableDataChanged();
	}
}
