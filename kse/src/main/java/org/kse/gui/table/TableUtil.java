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

import java.awt.BorderLayout;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;

import org.kse.gui.KeyStoreTableCellRend;
import org.kse.gui.KeyStoreTableColumns;
import org.kse.gui.KeyStoreTableHeadRend;
import org.kse.gui.TableColumnAdjuster;

/**
 * A utility class for common table functions.
 */
public class TableUtil {

    private static final int ICON_SIZE = 28;

    // Utility pattern
    private TableUtil() {}

    /**
     * Resizes a given set of column numbers to the icon size.
     * @param table The table with columns displaying icons.
     * @param columnNumbers The columns of the table that will display icons.
     */
    public static void setColumnsToIconSize(JTable table, int... columnNumbers) {
        for (int i : columnNumbers) {
            TableColumn typeCol = table.getColumnModel().getColumn(i);
            typeCol.setResizable(false);
            typeCol.setMinWidth(ICON_SIZE);
            typeCol.setMaxWidth(ICON_SIZE);
            typeCol.setPreferredWidth(ICON_SIZE);
        }
    }

    /**
     * Adds the customer renderers for tables that use the KeyStoreTableColumns.
     * @param table The table configurable by KeyStoreTableColumns.
     * @param keyStoreTableColumns The KeyStoreTableColumns for the table.
     */
    public static void addCustomRenderers(JTable table, KeyStoreTableColumns keyStoreTableColumns) {
        for (int i = 0; i < table.getColumnCount(); i++) {
            TableColumn column = table.getColumnModel().getColumn(i);

            column.setHeaderRenderer(
                    new KeyStoreTableHeadRend(table.getTableHeader().getDefaultRenderer()));
            column.setCellRenderer(new KeyStoreTableCellRend());
        }
    }

    // For quick testing
    public static void main(String[] args) {
        ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

        javax.swing.SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("KseTable");
            frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

            String[] columnNames = { "T", "L", "E", res.getString("KeyStoreTableModel.NameColumn"),
                                     res.getString("KeyStoreTableModel.AlgorithmColumn"),
                                     res.getString("KeyStoreTableModel.KeySizeColumn"),
                                     res.getString("KeyStoreTableModel.CertExpiryColumn"),
                                     res.getString("KeyStoreTableModel.SubjectDNColumn"),
                                     res.getString("KeyStoreTableModel.LastModifiedColumn"), };
            Object[][] data = {
                    { "KEY_PAIR", false, "NOT_EXPIRED", "mykey", "RSA", "2048", "2035-12-31",
                      "CN=Subject A, O=Organisation A, C=UK", "2034-01-15" },
                    { "TRUST_CERT", null, "NOT_EXPIRED", "trustedcert", "RSA", "4096", "2026-06-30",
                      "CN=Subject A, OU=Organizational Unit A, O=Organisation A, C=UK", "2024-01-10" },
                    { "KEY", true, null, "secretkey", "AES", "256", "-", "CN=A", "2024-01-20" }
            };

            JTable table = new JTable(data, columnNames);
            table.setShowGrid(false);
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            table.getTableHeader().setReorderingAllowed(false);
            table.setRowHeight(Math.max(18, table.getRowHeight()));
            setColumnsToIconSize(table, 0, 1, 2);

            KeyStoreTableColumns keyStoreTableColumns = new KeyStoreTableColumns();

            addCustomRenderers(table, keyStoreTableColumns);
            new TableColumnAdjuster(table, keyStoreTableColumns).adjustColumns();

            JScrollPane scrollPane = new JScrollPane(table);
            scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
            scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

            frame.add(scrollPane, BorderLayout.CENTER);

            JLabel statusLabel = new JLabel("KseTable");
            statusLabel.setBorder(new EmptyBorder(5, 5, 5, 5));
            frame.add(statusLabel, BorderLayout.SOUTH);

            frame.setSize(1000, 350);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}
