package org.kse.gui;

import java.util.Vector;

import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

public class JKseTable extends JTable {

	private static final long serialVersionUID = 6624687599136560793L;

	public JKseTable() {
		super();
		fixRowHeight();
	}

	public JKseTable(int numRows, int numColumns) {
		super(numRows, numColumns);
		fixRowHeight();
	}

	public JKseTable(Object[][] rowData, Object[] columnNames) {
		super(rowData, columnNames);
		fixRowHeight();
	}

	public JKseTable(TableModel dm, TableColumnModel cm, ListSelectionModel sm) {
		super(dm, cm, sm);
		fixRowHeight();
	}

	public JKseTable(TableModel dm, TableColumnModel cm) {
		super(dm, cm);
		fixRowHeight();
	}

	public JKseTable(TableModel dm) {
		super(dm);
		fixRowHeight();
	}

	public JKseTable(Vector<? extends Vector> rowData, Vector<?> columnNames) {
		super(rowData, columnNames);
		fixRowHeight();
	}

	private void fixRowHeight() {
		// workaround for default rowHeight not DPI scaled (https://bugs.openjdk.java.net/browse/JDK-8029087)
		int fontHeight = getFontMetrics(getFont()).getHeight();
		setRowHeight(fontHeight + (int) (0.2 * fontHeight + 0.5));
	}
}
