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
package org.kse.gui.dialogs.extensions;

import java.awt.Component;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;

/**
 * Custom cell renderer for the headers of the Extensions table.
 */
public class ExtensionsTableHeadRend extends DefaultTableCellRenderer {
    private static final long serialVersionUID = 1L;

    private TableCellRenderer delegate;

    /**
     * Constructs a new KeyStoreTableHeadRend instance.
     *
     * @param delegate The delegate for rendering the table column header.
     */
    public ExtensionsTableHeadRend(TableCellRenderer delegate) {
        this.delegate = delegate;
    }

    /**
     * Returns the rendered header cell for the supplied value and column.
     *
     * @param jtExtensions The JTable
     * @param value        The value to assign to the cell
     * @param isSelected   True if cell is selected
     * @param row          The row of the cell to render
     * @param col          The column of the cell to render
     * @param hasFocus     If true, render cell appropriately
     * @return The rendered cell
     */
    @Override
    public Component getTableCellRendererComponent(JTable jtExtensions, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int col) {

        Component c = delegate.getTableCellRendererComponent(jtExtensions, value, isSelected, hasFocus, row, col);

        if (c instanceof JLabel) {
            JLabel header = (JLabel) c;

            // The Critical header contains an icon
            if (col == 0) {
                header.setText("");
                ImageIcon icon = new ImageIcon(getClass().getResource("images/table/critical_heading.png"));
                header.setIcon(icon);
                header.setHorizontalAlignment(CENTER);
                header.setVerticalAlignment(CENTER);
            } else {
                // The other headers contain text
                header.setText(value.toString());
                header.setHorizontalAlignment(LEFT);
            }
        }

        return c;
    }
}
