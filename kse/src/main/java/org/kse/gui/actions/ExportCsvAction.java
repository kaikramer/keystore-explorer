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

package org.kse.gui.actions;

import java.awt.Toolkit;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.DecimalFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.table.TableColumnModel;

import org.kse.KSE;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DExportCsv;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to export the active KeyStore table as CSV.
 */
public class ExportCsvAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;
    private static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public ExportCsvAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_X,
                Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() + InputEvent.ALT_DOWN_MASK));
        putValue(LONG_DESCRIPTION, res.getString("ExportCsvAction.statusbar"));
        putValue(NAME, res.getString("ExportCsvAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("ExportCsvAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/exportcsv.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

            DExportCsv dExportCsv = new DExportCsv(frame, history.getName());
            dExportCsv.setLocationRelativeTo(frame);
            dExportCsv.setVisible(true);

            if (dExportCsv.exportSelected()) {
                exportFile(kseFrame.getActiveKeyStoreTable(), dExportCsv.getExportFile());
                JOptionPane.showMessageDialog(frame, res.getString("ExportCsvAction.ExportSuccessful.message"),
                        res.getString("ExportCsvAction.ExportCsv.Title"),
                        JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private void exportFile(JTable table, File exportFile) throws IOException {
        char listSeparator = getListSeparator();
        try (PrintStream csvOut = new PrintStream(exportFile, StandardCharsets.UTF_8)) {
            int columnCount = table.getColumnCount();

            TableColumnModel columnModel = table.getTableHeader().getColumnModel();
            for (int col = 0; col < columnCount; ++col) {
                csvOut.print("\"");
                csvOut.print(columnModel.getColumn(col).getHeaderValue());
                csvOut.print("\"");
                if (col < columnCount - 1) {
                    csvOut.print(listSeparator);
                }
            }
            csvOut.println();

            for (int row = 0; row < table.getRowCount(); ++row) {
                for (int col = 0; col < columnCount; ++col) {
                    Object value = table.getValueAt(row, col);

                    // Only the lock column will contain nulls, but this will catch anything.
                    if (value == null) {
                        value = "-";
                    }
                    if (value instanceof Date) {
                        value = DATE_FORMAT.format(value);
                    }
                    csvOut.print("\"");
                    csvOut.print(String.valueOf(value).replaceAll("\"","\"\""));
                    csvOut.print("\"");
                    if (col < columnCount - 1) {
                        csvOut.print(listSeparator);
                    }
                }
                csvOut.println();
            }
        }
    }

    private char getListSeparator() {
        // Infer the list separator by inspecting the decimal separator of the system locale.
        // Default is the comma, but if the decimal separator is a comma, like in Europe,
        // switch the list separator to a semicolon.
        char listSeparator = ',';
        if (',' == DecimalFormatSymbols.getInstance(KSE.SYSTEM_LOCALE).getDecimalSeparator()) {
            listSeparator = ';';
        }
        return listSeparator;
    }
}
