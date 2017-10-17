package org.kse.gui.crypto;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.table.AbstractTableModel;

public class GeneralTableModel<T> extends AbstractTableModel {
	private static final long serialVersionUID = 565000413120568901L;
	
	private String[] columnNames;
	private List<T> data = new ArrayList<T>();
	
	public GeneralTableModel(List<T> data, String ... columnNames) {
		this.columnNames = columnNames;
		this.data = data;
	}
	
	@Override
	public String getColumnName(int col) {
		return columnNames[col];
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	@Override
	public int getRowCount() {
		return data.size();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		return getRow(rowIndex);
	}

	@Override
	public boolean isCellEditable(int row, int col) {
		return false;
	}
	
	public void addRow(T object) {
		data.add(object);
		fireTableDataChanged();
	}
	
	public T getRow(int rowIndex) {
		return data.get(rowIndex);
	}
	
	public void removeRow(int row) {
		data.remove(row);
		fireTableDataChanged();
	}
	
	public List<T> getData() {
		return Collections.unmodifiableList(data);
	}
}
