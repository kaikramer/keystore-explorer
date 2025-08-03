/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

import static javax.swing.JTable.AUTO_RESIZE_ALL_COLUMNS;
import static javax.swing.JTable.AUTO_RESIZE_NEXT_COLUMN;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

/*
 * Class to manage the widths of columns in a table.
 *
 * Original version: https://tips4java.wordpress.com/2008/11/10/table-column-adjuster/
 */
public class TableColumnAdjuster implements PropertyChangeListener, TableModelListener {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

    private final JKseTable table;
    private final KeyStoreTableColumns keyStoreTableColumns;

    private static final double FF = 0.7; // fudge factor for font size to column size
    private static final int iFontSize = (int) (LnfUtil.getDefaultFontSize() * FF);

    // Additional spacing added to the column width
    private final int spacing = iFontSize * 2;

    // Include the data in the width calculations
    private final boolean isColumnDataIncluded = true;

    // Never shrink column width below preferred width
    private final boolean isOnlyAdjustLarger = false;

    // Indicates whether changes to the model should cause the width to be dynamically recalculated.
    private final boolean isDynamicAdjustment = true;

    private final Map<TableColumn, Integer> columnSizes = new HashMap<>();

    /*
     * Specify the table and use default spacing
     */
    public TableColumnAdjuster(JKseTable table, KeyStoreTableColumns keyStoreTableColumns) {
        this.table = table;
        this.keyStoreTableColumns = keyStoreTableColumns;
        setDynamicAdjustment(isDynamicAdjustment);
    }

    /*
     * Adjust the widths of all the columns in the table
     */
    public void adjustColumns() {
        // setting the auto resize mode to AUTO_RESIZE_ALL_COLUMNS allows the table to recalculate after every adjustment
        setMinMaxPreferred();
        table.setAutoResizeMode(AUTO_RESIZE_ALL_COLUMNS);

        TableColumnModel tcm = table.getColumnModel();

        for (int i = 0; i < tcm.getColumnCount(); i++) {
            adjustColumn(i);
        }

        // setting it to AUTO_RESIZE_NEXT_COLUMN after we are done make manual adjustments possible again
        SwingUtilities.invokeLater(() -> {
            table.setAutoResizeMode(AUTO_RESIZE_NEXT_COLUMN);
            unsetMinMaxPreferred();
        });
    }

    /*
     * Adjust the width of the specified column in the table
     */
    private void adjustColumn(final int column) {
        TableColumn tableColumn = table.getColumnModel().getColumn(column);

        if (!tableColumn.getResizable()) {
            return;
        }

        int columnHeaderWidth = getColumnHeaderWidth(column);
        int columnDataWidth = getColumnDataWidth(column);
        int preferredWidth = Math.max(columnHeaderWidth, columnDataWidth);

        updateTableColumn(column, preferredWidth);
    }

    /*
     * Calculated the width based on the column name
     */
    private int getColumnHeaderWidth(int column) {
        TableColumn tableColumn = table.getColumnModel().getColumn(column);
        Object value = tableColumn.getHeaderValue();
        TableCellRenderer renderer = tableColumn.getHeaderRenderer();

        if (renderer == null) {
            renderer = table.getTableHeader().getDefaultRenderer();
        }

        Component c = renderer.getTableCellRendererComponent(table, value, false, false, -1, column);
        return c.getPreferredSize().width;
    }

    /*
     * Calculate the width based on the widest cell renderer for the given column.
     */
    private int getColumnDataWidth(int column) {
        if (!isColumnDataIncluded) {
            return 0;
        }

        int preferredWidth = 0;
        int maxWidth = table.getColumnModel().getColumn(column).getMaxWidth();

        for (int row = 0; row < table.getRowCount(); row++) {
            preferredWidth = Math.max(preferredWidth, getCellDataWidth(row, column));

            // We've exceeded the maximum width, no need to check other rows
            if (preferredWidth >= maxWidth) {
                break;
            }
        }

        return preferredWidth;
    }

    /*
     * Get the preferred width for the specified cell
     */
    private int getCellDataWidth(int row, int column) {
        TableCellRenderer cellRenderer = table.getCellRenderer(row, column);
        Component c = table.prepareRenderer(cellRenderer, row, column);
        return c.getPreferredSize().width + table.getIntercellSpacing().width;
    }

    /*
     * Update the TableColumn with the newly calculated width
     */
    private void updateTableColumn(int column, int width) {
        final TableColumn tableColumn = table.getColumnModel().getColumn(column);

        if (!tableColumn.getResizable()) {
            return;
        }

        width += spacing;

        if (isOnlyAdjustLarger) {
            width = Math.max(width, tableColumn.getPreferredWidth());
        }

        columnSizes.put(tableColumn, tableColumn.getWidth());

        table.getTableHeader().setResizingColumn(tableColumn);
        tableColumn.setWidth(width);
    }

    private void setDynamicAdjustment(boolean isDynamicAdjustment) {
        if (isDynamicAdjustment) {
            table.addPropertyChangeListener(this);
            table.getModel().addTableModelListener(this);
        }
    }

    private void setMinMaxPreferred() {
        int columnCount = table.getColumnModel().getColumnCount();

        for (int i = 0; i < columnCount; i++) {
            TableColumn column = table.getColumnModel().getColumn(i);

            int width = 0;
            for (int row = 0; row < table.getRowCount(); row++) {
                width = 0;
                TableCellRenderer renderer = table.getCellRenderer(row, i);
                Component comp = renderer.getTableCellRendererComponent(table, table.getValueAt(row, i),
                                                                        false, false, row, i);
                width = Math.max(width, comp.getPreferredSize().width);
            }
            int l = (int) Math.round((double) width / iFontSize);

            if (i == keyStoreTableColumns.colIndexEntryName()) {
                column.setMinWidth(res.getString("KeyStoreTableModel.NameColumn").length() * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.NameColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.NameColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIndexAlgorithm()) {
                column.setMinWidth((4) * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.AlgorithmColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.AlgorithmColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIndexKeySize()) {
                column.setMinWidth((4) * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.KeySizeColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.KeySizeColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIndexCurve()) {
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(res.getString("KeyStoreTableModel.CurveColumn").length(), l) * iFontSize);
                column.setMaxWidth(2 + Math.max("brainpool999r1".length(),
                                                res.getString("KeyStoreTableModel.CurveColumn").length()) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIndexCertificateValidityStart()) {
                l = "20.09.2000, 00:00:00 PM CEST".length();
                column.setMinWidth("20.00.2000".length() * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.CertExpiryColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.CertExpiryColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIndexCertificateExpiry()) {
                l = "20.09.2000, 00:00:00 PM CEST".length();
                column.setMinWidth("20.00.2000".length() * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.CertExpiryColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.CertExpiryColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIndexLastModified()) {
                l = "20.09.2000, 00:00:00 PM CEST".length();
                column.setMinWidth("20.00.2000".length() * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.LastModifiedColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.LastModifiedColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIndexAKI()) {
                l = 42;
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(res.getString("KeyStoreTableModel.AKIColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(res.getString("KeyStoreTableModel.AKIColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIndexSKI()) {
                l = 42;
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(res.getString("KeyStoreTableModel.SKIColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(res.getString("KeyStoreTableModel.SKIColumn").length(), l) * iFontSize);
            }
        }
    }

    private void unsetMinMaxPreferred() {
        int columnCount = table.getColumnModel().getColumnCount();
        int minWidth = 15; // minimum width for all columns, taken from TableColumn.java
        int maxWidth = Integer.MAX_VALUE; // maximum width for all columns, taken from TableColumn.java

        // reset min/max column widths to make resizing for user easier/possible again
        for (int i = 0; i < columnCount; i++) {
            TableColumn column = table.getColumnModel().getColumn(i);

            if (i == keyStoreTableColumns.colIndexEntryName()) {
                column.setMinWidth(minWidth);
                column.setMaxWidth(maxWidth);
            }
            if (i == keyStoreTableColumns.colIndexAlgorithm()) {
                column.setMinWidth(minWidth);
                column.setMaxWidth(maxWidth);
            }
            if (i == keyStoreTableColumns.colIndexKeySize()) {
                column.setMinWidth(minWidth);
                column.setMaxWidth(maxWidth);
            }
            if (i == keyStoreTableColumns.colIndexCurve()) {
                column.setMinWidth(minWidth);
                column.setMaxWidth(maxWidth);
            }
            if (i == keyStoreTableColumns.colIndexCertificateExpiry()) {
                column.setMinWidth(minWidth);
                column.setMaxWidth(maxWidth);
            }
            if (i == keyStoreTableColumns.colIndexLastModified()) {
                column.setMinWidth(minWidth);
                column.setMaxWidth(maxWidth);
            }
            if (i == keyStoreTableColumns.colIndexAKI()) {
                column.setMinWidth(minWidth);
                column.setMaxWidth(maxWidth);
            }
            if (i == keyStoreTableColumns.colIndexSKI()) {
                column.setMinWidth(minWidth);
                column.setMaxWidth(maxWidth);
            }
        }
    }

    @Override
    public void propertyChange(PropertyChangeEvent e) {
        // When the TableModel changes we need to update the listeners and column widths
        if ("model".equals(e.getPropertyName())) {
            TableModel model = (TableModel) e.getOldValue();
            model.removeTableModelListener(this);

            model = (TableModel) e.getNewValue();
            model.addTableModelListener(this);
            adjustColumns();
        }
    }

    @Override
    public void tableChanged(final TableModelEvent e) {
        if (!isColumnDataIncluded) {
            return;
        }

        // Needed when table is sorted.
        SwingUtilities.invokeLater(() -> {
            // A cell has been updated
            int column = table.convertColumnIndexToView(e.getColumn());

            if (e.getType() == TableModelEvent.UPDATE && column != -1) {

                // Only need to worry about an increase in width for this cell
                if (isOnlyAdjustLarger) {
                    int row = e.getFirstRow();
                    TableColumn tableColumn = table.getColumnModel().getColumn(column);

                    if (tableColumn.getResizable()) {
                        int width = getCellDataWidth(row, column);
                        updateTableColumn(column, width);
                    }
                } else {
                    // Could be an increase of decrease so check all rows
                    adjustColumn(column);
                }
            } else {
                // The update affected more than one column so adjust all columns
                adjustColumns();
            }
        });
    }
}