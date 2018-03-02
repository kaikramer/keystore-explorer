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
package org.kse.gui.dialogs.extensions;

import java.awt.Component;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Custom cell renderer for the cells of the Extensions table.
 *
 */
public class ExtensionsTableCellRend extends DefaultTableCellRenderer {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	/**
	 * Returns the rendered cell.
	 *
	 * @param jtExtensions
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
	public Component getTableCellRendererComponent(JTable jtExtensions, Object value, boolean isSelected,
			boolean hasFocus, int row, int col) {
		JLabel cell = (JLabel) super.getTableCellRendererComponent(jtExtensions, value, isSelected, hasFocus, row, col);

		// Critical column - display an icon representing criticality and
		// tool-tip text
		if (col == 0) {
			ImageIcon icon = null;

			if (((Boolean) value).booleanValue()) {
				icon = new ImageIcon(getClass().getResource(
						res.getString("ExtensionsTableCellRend.CriticalExtension.image")));
				cell.setToolTipText(res.getString("ExtensionsTableCellRend.CriticalExtension.tooltip"));
			} else {
				icon = new ImageIcon(getClass().getResource(
						res.getString("ExtensionsTableCellRend.NonCriticalExtension.image")));
				cell.setToolTipText(res.getString("ExtensionsTableCellRend.NonCriticalExtension.tooltip"));
			}

			cell.setIcon(icon);
			cell.setText("");
			cell.setVerticalAlignment(CENTER);
			cell.setHorizontalAlignment(CENTER);
		}
		// Name column - may be unknown
		else if (col == 1) {
			if (cell.getText().length() == 0) {
				cell.setText("-");
				cell.setHorizontalAlignment(CENTER);
			} else {
				cell.setHorizontalAlignment(LEFT);
			}
		} else {
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) value;
			cell.setText(oid.getId());
		}

		cell.setBorder(new EmptyBorder(0, 5, 0, 5));

		return cell;
	}
}
