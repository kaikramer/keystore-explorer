/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2022 Kai Kramer
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

	public JKseTable(Vector<? extends Vector<?>> rowData, Vector<?> columnNames) {
		super(rowData, columnNames);
		fixRowHeight();
	}

	private void fixRowHeight() {
		// workaround for default rowHeight not DPI scaled (https://bugs.openjdk.java.net/browse/JDK-8029087)
		int fontHeight = getFontMetrics(getFont()).getHeight();
		setRowHeight(fontHeight + (int) (0.2 * fontHeight + 0.5));
	}
}
