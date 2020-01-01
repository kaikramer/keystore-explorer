/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
import java.util.Date;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import org.bouncycastle.util.encoders.Hex;
import org.kse.utilities.StringUtils;

/**
 * Custom cell renderer for the cells of the KeyStore table of KeyStore
 * Explorer.
 *
 */
public class KeyStoreTableCellRend extends DefaultTableCellRenderer {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

	/**
	 * Returns the rendered cell for the supplied value and column.
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

		JLabel cell = (JLabel) super.getTableCellRendererComponent(jtKeyStore, value, isSelected, hasFocus, row, col);

		// Entry Type column - display an icon representing the type and tool-tip text
		if (col == 0) {
			ImageIcon icon = null;

			if (KeyStoreTableModel.KEY_PAIR_ENTRY.equals(value)) {
				icon = new ImageIcon(getClass().getResource(
						"images/table/keypair_entry.png"));
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.KeyPairEntry.tooltip"));
			} else if (KeyStoreTableModel.TRUST_CERT_ENTRY.equals(value)) {
				icon = new ImageIcon(getClass().getResource(
						"images/table/trustcert_entry.png"));
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.TrustCertEntry.tooltip"));
			} else {
				icon = new ImageIcon(getClass().getResource("images/table/key_entry.png"));
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.KeyEntry.tooltip"));
			}

			cell.setIcon(icon);
			cell.setText("");
			cell.setVerticalAlignment(CENTER);
			cell.setHorizontalAlignment(CENTER);
		}
		// Lock column - if entry is a key or key pair display an icon for the lock status
		else if (col == 1) {
			if (value == null) {
				// No lock status available (not a key pair entry or PKCS #12 KeyStore)
				cell.setIcon(null);
				cell.setText("-");
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.NoLockStatus.tooltip"));
				cell.setHorizontalAlignment(CENTER);
			} else {
				ImageIcon icon = null;

				if (value.equals(Boolean.TRUE)) {
					// Locked
					icon = new ImageIcon(getClass().getResource(
							"images/table/locked_entry.png"));
					cell.setToolTipText(res.getString("KeyStoreTableCellRend.LockedEntry.tooltip"));
				} else {
					// Unlocked
					icon = new ImageIcon(getClass().getResource(
							"images/table/unlocked_entry.png"));
					cell.setToolTipText(res.getString("KeyStoreTableCellRend.UnlockedEntry.tooltip"));
				}

				cell.setIcon(icon);
				cell.setText("");
				cell.setVerticalAlignment(CENTER);
				cell.setHorizontalAlignment(CENTER);
			}
		}
		// Expiry column - if entry is a key pair display an icon for the expired/unexpired
		else if (col == 2) {
			if (value == null) {
				// No cert expired status available (must be a key entry)
				cell.setIcon(null);
				cell.setText("-");
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.NoCertExpiry.tooltip"));
				cell.setHorizontalAlignment(CENTER);
			} else {
				ImageIcon icon = null;
				if (value.equals(2)) {
					// Expired
					icon = new ImageIcon(getClass().getResource(
							"images/table/cert_expired_entry.png"));
					cell.setToolTipText(res.getString("KeyStoreTableCellRend.CertExpiredEntry.tooltip"));
				} else {
					if (value.equals(1)) {
						// Almost Expired
						icon = new ImageIcon(getClass()
								.getResource("images/table/cert_old_entry.png"));
						cell.setToolTipText(res.getString("KeyStoreTableCellRend.CertAlmostExpiredEntry.tooltip"));
					} else {
					// Unexpired
					icon = new ImageIcon(getClass().getResource(
							"images/table/cert_unexpired_entry.png"));
					cell.setToolTipText(res.getString("KeyStoreTableCellRend.CertUnexpiredEntry.tooltip"));
				}
				}

				cell.setIcon(icon);
				cell.setText("");
				cell.setVerticalAlignment(CENTER);
				cell.setHorizontalAlignment(CENTER);
			}
		}
		// Generic columns 
		else {
			return writeCell(cell, value);
		}

		return cell;
	}

	private JLabel writeCell(JLabel cell, Object value) {
		try {
			if (value == null) {
				cell.setText("-");
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.Unavailable.tooltip"));
				cell.setHorizontalAlignment(CENTER);
			} else {
				if (value instanceof String) {
					String algorithm = (String) value;
					cell.setText(algorithm);
					cell.setToolTipText(getText());
					cell.setHorizontalAlignment(LEFT);
				} else {
					if (value instanceof Integer) {
						if (((Integer) value < 10000) && ((Integer) value >= 0))
							cell.setText(String.valueOf(value));
						else
							cell.setText("X" + String.format("%x", value));
						cell.setToolTipText(getText());
						cell.setHorizontalAlignment(LEFT);
					} else {
						if (value instanceof Date) {
							cell.setText(StringUtils.formatDate((Date) value));
							cell.setToolTipText(getText());
							cell.setHorizontalAlignment(LEFT);
						} else {
							if (value instanceof byte[]) {
								cell.setText(Hex.toHexString((byte[]) value));
								cell.setToolTipText(getText());
								cell.setHorizontalAlignment(LEFT);
							}
						}
					}
				}
			}
		} catch (Exception e) {
			cell.setText("?");
			cell.setToolTipText(res.getString("KeyStoreTableCellRend.Format.tooltip"));
			cell.setHorizontalAlignment(CENTER);
		}

		return cell;
	}
}
