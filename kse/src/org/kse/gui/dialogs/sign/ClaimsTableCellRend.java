package org.kse.gui.dialogs.sign;

import java.awt.Component;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * 
 * Custom cell renderer for the cells of list custom claims.
 */
public class ClaimsTableCellRend extends DefaultTableCellRenderer {

	private static final long serialVersionUID = 1L;


	@Override
	public Component getTableCellRendererComponent(JTable jtClaims, Object value, boolean isSelected,
			boolean hasFocus, int row, int col) {
		JLabel cell = (JLabel) super.getTableCellRendererComponent(jtClaims, value, isSelected, hasFocus, row,
				col);

		cell.setText((String)value);

		cell.setBorder(new EmptyBorder(0, 5, 0, 5));

		return cell;
	}
}
