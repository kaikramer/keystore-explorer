/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
package org.kse.gui.crypto.policyinformation;

import java.awt.Component;
import java.io.IOException;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.kse.crypto.x509.PolicyInformationUtil;

/**
 * Custom cell renderer for the cells of the policy qualifier info table.
 *
 */
public class PolicyQualifierInfoTableCellRend extends DefaultTableCellRenderer {
	private static final long serialVersionUID = 1L;

	/**
	 * Returns the rendered cell.
	 *
	 * @param jtPolicyQualifierInfo
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
	public Component getTableCellRendererComponent(JTable jtPolicyQualifierInfo, Object value, boolean isSelected,
			boolean hasFocus, int row, int col) {
		JLabel cell = (JLabel) super.getTableCellRendererComponent(jtPolicyQualifierInfo, value, isSelected, hasFocus,
				row, col);

		PolicyQualifierInfo policyQualifierInfo = (PolicyQualifierInfo) value;

		try {
			String policyQualifierInfoStr = PolicyInformationUtil.toString(policyQualifierInfo);
			cell.setText(policyQualifierInfoStr);
			cell.setToolTipText(policyQualifierInfoStr);
		} catch (IOException ex) {
			throw new RuntimeException(ex); // We build this data so should not
			// happen
		}

		cell.setHorizontalAlignment(LEFT);
		cell.setBorder(new EmptyBorder(0, 5, 0, 5));

		return cell;
	}
}
