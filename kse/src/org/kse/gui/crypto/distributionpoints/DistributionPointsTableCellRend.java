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

package org.kse.gui.crypto.distributionpoints;

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Custom cell renderer for the cells of the general names table.
 */
public class DistributionPointsTableCellRend extends DefaultTableCellRenderer {
    private static final long serialVersionUID = 1L;

    /**
     * Returns the rendered cell.
     *
     * @param jtDistributionPoints The JTable
     * @param value          The value to assign to the cell
     * @param isSelected     True if cell is selected
     * @param row            The row of the cell to render
     * @param col            The column of the cell to render
     * @param hasFocus       If true, render cell appropriately
     * @return The rendered cell
     */
    @Override
    public Component getTableCellRendererComponent(JTable jtDistributionPoints, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int col) {
        JLabel cell = (JLabel) super.getTableCellRendererComponent(jtDistributionPoints, value, isSelected, hasFocus,
                                                                   row, col);

        String distributionPointStr = "Distribution Point " + (row + 1);
        cell.setText(distributionPointStr);
        cell.setToolTipText(distributionPointStr);

        cell.setHorizontalAlignment(LEFT);
        cell.setBorder(new EmptyBorder(0, 5, 0, 5));

        return cell;
    }
}
