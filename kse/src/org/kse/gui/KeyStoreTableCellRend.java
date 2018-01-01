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
import java.text.MessageFormat;
import java.util.Date;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

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
						res.getString("KeyStoreTableCellRend.KeyPairEntry.image")));
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.KeyPairEntry.tooltip"));
			} else if (KeyStoreTableModel.TRUST_CERT_ENTRY.equals(value)) {
				icon = new ImageIcon(getClass().getResource(
						res.getString("KeyStoreTableCellRend.TrustCertEntry.image")));
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.TrustCertEntry.tooltip"));
			} else {
				icon = new ImageIcon(getClass().getResource(res.getString("KeyStoreTableCellRend.KeyEntry.image")));
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
							res.getString("KeyStoreTableCellRend.LockedEntry.image")));
					cell.setToolTipText(res.getString("KeyStoreTableCellRend.LockedEntry.tooltip"));
				} else {
					// Unlocked
					icon = new ImageIcon(getClass().getResource(
							res.getString("KeyStoreTableCellRend.UnlockedEntry.image")));
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

				if (value.equals(Boolean.TRUE)) {
					// Expired
					icon = new ImageIcon(getClass().getResource(
							res.getString("KeyStoreTableCellRend.CertExpiredEntry.image")));
					cell.setToolTipText(res.getString("KeyStoreTableCellRend.CertExpiredEntry.tooltip"));
				} else {
					// Unexpired
					icon = new ImageIcon(getClass().getResource(
							res.getString("KeyStoreTableCellRend.CertUnexpiredEntry.image")));
					cell.setToolTipText(res.getString("KeyStoreTableCellRend.CertUnexpiredEntry.tooltip"));
				}

				cell.setIcon(icon);
				cell.setText("");
				cell.setVerticalAlignment(CENTER);
				cell.setHorizontalAlignment(CENTER);
			}
		}
		// Algorithm column - algorithm name
		else if (col == 4) {
			String algorithm = (String) value;

			if (algorithm == null) {
				// No algorithm name available
				cell.setText("-");
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.NoAlgorithm.tooltip"));
				cell.setHorizontalAlignment(CENTER);
			} else {
				cell.setText(algorithm);
				cell.setToolTipText(getText());
				cell.setHorizontalAlignment(LEFT);
			}
		}
		// Key Size column - key size (if known)
		else if (col == 5) {
			Integer keySize = (Integer) value;

			if (keySize == null) {
				// No key size available
				cell.setText("-");
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.NoKeySize.tooltip"));
				cell.setHorizontalAlignment(CENTER);
			} else {
				cell.setText("" + keySize);
				cell.setToolTipText(getText());
				cell.setHorizontalAlignment(LEFT);
			}
		}
		// Certificate Expiry column - format date (if any) and indicate any expiry
		else if (col == 6) {
			if (value != null) {
				cell.setText(StringUtils.formatDate((Date) value));
				cell.setHorizontalAlignment(LEFT);

				// If expiry passed add to the tool tip to suggest expiry
				if (new Date().after((Date) value)) {
					cell.setToolTipText(MessageFormat.format(
							res.getString("KeyStoreTableCellRend.ExpiredEntry.tooltip"), getText()));
				}
				// Otherwise clear any icon and set tooltip as date/time
				else {
					cell.setToolTipText(getText());
				}
			} else {
				// No expiry date/time available (no certificates in KeyStore entry)
				cell.setText("-");
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.NoCertExpiry.tooltip"));
				cell.setHorizontalAlignment(CENTER);
				cell.setIcon(null);
			}
		}
		// Last Modified column - format date (if any)
		else if (col == 7) {
			if (value != null) {
				cell.setText(StringUtils.formatDate((Date) value));
				cell.setToolTipText(getText());
				cell.setHorizontalAlignment(LEFT);
			} else {
				// No last modified date/time available (PKCS #12 KeyStore)
				cell.setText("-");
				cell.setToolTipText(res.getString("KeyStoreTableCellRend.NoLastModified.tooltip"));
				cell.setHorizontalAlignment(CENTER);
			}
		}
		// Alias column - just use alias text
		else {
			if (value != null) {
				cell.setText(value.toString());
				cell.setToolTipText(getText());
			}
		}

		return cell;
	}
}
