/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

import java.awt.Component;
import java.util.ResourceBundle;
import java.util.Vector;

import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

public class JKseTable extends JTable {

    private static final long serialVersionUID = 6624687599136560793L;
    private static final int ICON_SIZE = 28;
    private static final double FF = 0.7; // fudge factor for font size to column size
    private static int iFontSize = (int) (LnfUtil.getDefaultFontSize() * FF);
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

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

    public void setColumnsToIconSize(int... columnNumbers) {
        for (int i : columnNumbers) {
            TableColumn typeCol = getColumnModel().getColumn(i);
            typeCol.setResizable(false);
            typeCol.setMinWidth(ICON_SIZE);
            typeCol.setMaxWidth(ICON_SIZE);
            typeCol.setPreferredWidth(ICON_SIZE);
        }
    }

    public void colAdjust(KeyStoreTableColumns keyStoreTableColumns, int autoResizeMode) {
        setAutoResizeMode(autoResizeMode);
        // Add custom renderers for headers and cells
        for (int i = 0; i < getColumnCount(); i++) {
            int width = 0;
            TableColumn column = getColumnModel().getColumn(i);

            // new, size columns based on title. Columns are resizable by default
            // http://www.java2s.com/this/Java/0240__Swing/Setcolumnwidthbasedoncellrenderer.htm
            for (int row = 0; row < getRowCount(); row++) {
                width = 0;
                TableCellRenderer renderer = getCellRenderer(row, i);
                Component comp = renderer.getTableCellRendererComponent(this, getValueAt(row, i),
                                                                        false, false, row, i);
                width = Math.max(width, comp.getPreferredSize().width);
            }
            int l = width;

            if (i == keyStoreTableColumns.colEntryName()) {
                column.setMinWidth((2 + res.getString("KeyStoreTableModel.NameColumn")).length() * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.NameColumn").length(), 20) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.NameColumn").length(), 50) * iFontSize);
            }
            if (i == keyStoreTableColumns.colAlgorithm()) {
                column.setMinWidth((4) * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.AlgorithmColumn").length(), 4) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.AlgorithmColumn").length(), 5) * iFontSize);
            }
            if (i == keyStoreTableColumns.colKeySize()) {
                column.setMinWidth((4) * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.KeySizeColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.KeySizeColumn").length(), l + 1) * iFontSize);
            }
            if (i == keyStoreTableColumns.colCurve()) {
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        1 + Math.max(res.getString("KeyStoreTableModel.CurveColumn").length(), l) * iFontSize);
                column.setMaxWidth(2 + Math.max("brainpool999r1".length(),
                                                res.getString("KeyStoreTableModel.CurveColumn").length()) * iFontSize);
            }
            if (i == keyStoreTableColumns.colCertificateExpiry()) {
                l = "20.00.2000 00:00:00 MESZ".length();
                column.setMinWidth("20.00.2000".length() * iFontSize);
                column.setPreferredWidth(
                        1 + Math.max(res.getString("KeyStoreTableModel.CertExpiryColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        2 + Math.max(res.getString("KeyStoreTableModel.CertExpiryColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colLastModified()) {
                l = "20.09.2000 00:00:00 MESZ".length();
                column.setMinWidth("20.00.2000".length() * iFontSize);
                column.setPreferredWidth(
                        1 + Math.max(res.getString("KeyStoreTableModel.LastModifiedColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        2 + Math.max(res.getString("KeyStoreTableModel.LastModifiedColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colAKI()) {
                l = 41;
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        1 + Math.max(res.getString("KeyStoreTableModel.AKIColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.AKIColumn").length(), (l + 1)) * iFontSize);
            }
            if (i == keyStoreTableColumns.colSKI()) {
                l = 41;
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.SKIColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.SKIColumn").length(), (l + 1)) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIssuerCN()) {
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.IssuerCNColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(100 * iFontSize);
            }
            if (i == keyStoreTableColumns.colIssuerDN()) {
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.IssuerDNColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(100 * iFontSize);
            }
            if (i == keyStoreTableColumns.colIssuerO()) {
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.IssuerOColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(100 * iFontSize);
            }
            column.setHeaderRenderer(
                    new KeyStoreTableHeadRend(getTableHeader().getDefaultRenderer(), keyStoreTableColumns));
            column.setCellRenderer(new KeyStoreTableCellRend());
        }
    }
}
