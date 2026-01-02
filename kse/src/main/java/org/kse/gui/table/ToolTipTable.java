/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

package org.kse.gui.table;

import java.awt.Point;
import java.awt.event.MouseEvent;

import javax.swing.JTable;
import javax.swing.table.JTableHeader;

/**
 * A JTable extension for automatically setting the column header tool tips. To
 * enable column header tool tips, the table model must extend ToolTipTableModel.
 */
public class ToolTipTable extends JTable {
    // https://docs.oracle.com/javase/tutorial/uiswing/components/table.html#headertooltip
    private static final long serialVersionUID = 1L;

    // Store reference here so don't need to cast from JTableModel.
    private ToolTipTableModel toolTipTableModel;

    /**
     * Constructs a JTable that is initialized with a ToolTipTableModel.
     *
     * @param tableModel The ToolTipTableModel.
     */
    public ToolTipTable(ToolTipTableModel tableModel) {
        super(tableModel);
        this.toolTipTableModel = tableModel;
    }

    // Constructor for JKseTable
    protected ToolTipTable(Object[][] rowData, Object[] columnNames) {
        super(rowData, columnNames);
    }

    @Override
    protected JTableHeader createDefaultTableHeader() {
        return new JTableHeader(columnModel) {
            @Override
            public String getToolTipText(MouseEvent event) {
                if (toolTipTableModel != null) {
                    Point p = event.getPoint();
                    int index = columnModel.getColumnIndexAtX(p.x);
                    int realIndex = columnModel.getColumn(index).getModelIndex();
                    return toolTipTableModel.getToolTip(realIndex);
                }
                return null;
            }
        };
    }
}
