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

import java.awt.BorderLayout;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;

import org.kse.gui.table.ToolTipTable;
import org.kse.gui.table.ToolTipTableModel;

public class JKseTable extends ToolTipTable {

    private static final long serialVersionUID = 6624687599136560793L;
    private static final int ICON_SIZE = 28;

    /**
     * @param tableModel
     */
    public JKseTable(ToolTipTableModel tableModel) {
        super(tableModel);
        fixRowHeight();
    }

    private JKseTable(Object[][] rowData, Object[] columnNames) {
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

    public void addCustomRenderers(KeyStoreTableColumns keyStoreTableColumns) {
        for (int i = 0; i < getColumnCount(); i++) {
            TableColumn column = getColumnModel().getColumn(i);

            column.setHeaderRenderer(
                    new KeyStoreTableHeadRend(getTableHeader().getDefaultRenderer(), keyStoreTableColumns));
            column.setCellRenderer(new KeyStoreTableCellRend());
        }
    }

    // For quick testing
    public static void main(String[] args) {
        ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

        javax.swing.SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("JKseTable");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            String[] columnNames = { "T", "L", "E", res.getString("KeyStoreTableModel.NameColumn"),
                                     res.getString("KeyStoreTableModel.AlgorithmColumn"),
                                     res.getString("KeyStoreTableModel.KeySizeColumn"),
                                     res.getString("KeyStoreTableModel.CertExpiryColumn"),
                                     res.getString("KeyStoreTableModel.SubjectDNColumn"),
                                     res.getString("KeyStoreTableModel.LastModifiedColumn"), };
            Object[][] data = {
                    { "\uD83D\uDD11", "❌", "\uD83D\uDD13", "mykey", "RSA", "2048", "2025-12-31",
                      "CN=Subject A, O=Organisation A, C=UK", "2024-01-15" },
                    { "\uD83D\uDDCE", "✅", "\uD83D\uDD13", "trustedcert", "RSA", "4096", "2026-06-30",
                      "CN=Subject A, OU=Organizational Unit A, O=Organisation A, C=UK", "2024-01-10" },
                    { "㊙", "✅", "\uD83D\uDD12", "secretkey", "AES", "256", "-", "CN=A", "2024-01-20" }
            };

            JKseTable table = new JKseTable(data, columnNames);
            table.setShowGrid(false);
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            table.getTableHeader().setReorderingAllowed(false);
            table.setRowHeight(Math.max(18, table.getRowHeight()));
            table.setColumnsToIconSize(0, 1, 2);

            KeyStoreTableColumns keyStoreTableColumns = new KeyStoreTableColumns();


            new TableColumnAdjuster(table, keyStoreTableColumns).adjustColumns();

            JScrollPane scrollPane = new JScrollPane(table);
            scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
            scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

            frame.add(scrollPane, BorderLayout.CENTER);

            JLabel statusLabel = new JLabel("JKseTable");
            statusLabel.setBorder(new EmptyBorder(5, 5, 5, 5));
            frame.add(statusLabel, BorderLayout.SOUTH);

            frame.setSize(1000, 350);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}
