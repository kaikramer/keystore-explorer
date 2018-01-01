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
package org.kse.gui;

import java.awt.Component;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;

/**
 * Custom cell renderer for the headers of the KeyStore table of KeyStore
 * Explorer.
 *
 */
public class KeyStoreTableHeadRend extends DefaultTableCellRenderer {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

	private TableCellRenderer delegate;

	public KeyStoreTableHeadRend(TableCellRenderer delegate) {
		this.delegate = delegate;
	}

	/**
	 * Returns the rendered header cell for the supplied value and column.
	 *
	 * @param jtKeyStore
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
	public Component getTableCellRendererComponent(JTable jtKeyStore, Object value, boolean isSelected,
			boolean hasFocus, int row, int col) {

		Component c = delegate.getTableCellRendererComponent(jtKeyStore, value, isSelected, hasFocus, row, col);

		if (c instanceof JLabel) {

			JLabel header = (JLabel) c;

			// The entry type header contains an icon (entry type)
			if (col == 0) {
				header.setText("");
				ImageIcon icon = new ImageIcon(getClass().getResource(
						res.getString("KeyStoreTableHeadRend.TypeColumn.image")));
				header.setIcon(icon);
				header.setHorizontalAlignment(CENTER);
				header.setVerticalAlignment(CENTER);

				header.setToolTipText(res.getString("KeyStoreTableHeadRend.TypeColumn.tooltip"));
			}
			// As does the lock status
			else if (col == 1) {
				header.setText("");
				ImageIcon icon = new ImageIcon(getClass().getResource(
						res.getString("KeyStoreTableHeadRend.LockStatusColumn.image")));
				header.setIcon(icon);
				header.setHorizontalAlignment(CENTER);
				header.setVerticalAlignment(CENTER);

				header.setToolTipText(res.getString("KeyStoreTableHeadRend.LockStatusColumn.tooltip"));
			}
			// And the expiry status
			else if (col == 2) {
				header.setText("");
				ImageIcon icon = new ImageIcon(getClass().getResource(
						res.getString("KeyStoreTableHeadRend.CertExpiryStatusColumn.image")));
				header.setIcon(icon);
				header.setHorizontalAlignment(CENTER);
				header.setVerticalAlignment(CENTER);

				header.setToolTipText(res.getString("KeyStoreTableHeadRend.CertExpiryStatusColumn.tooltip"));
			}
			// The other headers contain text
			else {
				header.setText((String) value);
				header.setHorizontalAlignment(LEFT);

				if (col == 3) {
					header.setToolTipText(res.getString("KeyStoreTableHeadRend.NameColumn.tooltip"));
				} else if (col == 4) {
					header.setToolTipText(res.getString("KeyStoreTableHeadRend.AlgorithmColumn.tooltip"));
				} else if (col == 5) {
					header.setToolTipText(res.getString("KeyStoreTableHeadRend.KeySizeColumn.tooltip"));
				} else if (col == 6) {
					header.setToolTipText(res.getString("KeyStoreTableHeadRend.CertExpiryColumn.tooltip"));
				} else {
					header.setToolTipText(res.getString("KeyStoreTableHeadRend.LastModifiedColumn.tooltip"));
				}
			}
		}

		return c;
	}
}
