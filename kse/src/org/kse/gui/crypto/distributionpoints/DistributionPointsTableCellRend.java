package org.kse.gui.crypto.distributionpoints;

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Custom cell renderer for the cells of the general names table.
 *
 */
public class DistributionPointsTableCellRend extends DefaultTableCellRenderer {
	private static final long serialVersionUID = 1L;

	/**
	 * Returns the rendered cell.
	 *
	 * @param jtGeneralNames
	 *            The JTable
	 * @param value
	 *            The value to assign to the cell
	 * @param isSelected
	 *            True if cell is selected
	 * @param row
	 *            The row of the cell to render
	 * @param col
	 *            The column of the cell to render
	 * @param hasFocus
	 *            If true, render cell appropriately
	 * @return The renderered cell
	 */
	@Override
	public Component getTableCellRendererComponent(JTable jtDistributionPoints, Object value, boolean isSelected,
			boolean hasFocus, int row, int col) {
		JLabel cell = (JLabel) super.getTableCellRendererComponent(jtDistributionPoints, value, isSelected, hasFocus, row,
				col);

		String distributionPointStr = "Distribution Point " + (row + 1);
		cell.setText(distributionPointStr);
		cell.setToolTipText(distributionPointStr);

		cell.setHorizontalAlignment(LEFT);
		cell.setBorder(new EmptyBorder(0, 5, 0, 5));

		return cell;
	}
}
