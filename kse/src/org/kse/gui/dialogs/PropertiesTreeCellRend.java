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
package org.kse.gui.dialogs;

import java.awt.Component;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeNode;

/**
 * Custom cell renderer for the cells of the DProperties tree.
 *
 */
public class PropertiesTreeCellRend extends DefaultTreeCellRenderer {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	/**
	 * Returns the rendered cell for the supplied value.
	 *
	 * @param jtrProperties
	 *            The JTree
	 * @param value
	 *            The value to assign to the cell
	 * @param isSelected
	 *            True if cell is selected
	 * @param isExpanded
	 *            True if cell is expanded
	 * @param leaf
	 *            True if cell is a leaf
	 * @param row
	 *            The row of the cell to render
	 * @param hasFocus
	 *            If true, render cell appropriately
	 * @return The renderered cell
	 */
	@Override
	public Component getTreeCellRendererComponent(JTree jtrProperties, Object value, boolean isSelected,
			boolean isExpanded, boolean leaf, int row, boolean hasFocus) {
		JLabel cell = (JLabel) super.getTreeCellRendererComponent(jtrProperties, value, isSelected, isExpanded, leaf,
				row, hasFocus);
		cell.setText(value.toString());

		// Get the correct icon for the node and set any tool tip text
		DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;

		ImageIcon icon = null;

		if (node.getLevel() == 1) // Second level - keystore main properties and
			// "keys", "key pairs"
			// and "trusted certificates"
		{
			TreeNode parent = node.getParent();
			int index = parent.getIndex(node);

			if (index == 0) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.File.image")));
			} else if (index == 1) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.Type.image")));
			} else if (index == 2) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.Provider.image")));
			} else if (index == 3) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.Keys.image")));
			} else if (index == 4) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.KeyPairs.image")));
			} else if (index == 5) {
				icon = new ImageIcon(getClass().getResource(
						res.getString("PropertiesTreeCellRend.TrustedCertificates.image")));
			}
		} else if (node.getLevel() == 2) // Third level - entries
		{
			icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.Entry.image")));
		} else if (node.getLevel() == 3) // Fourth level - includes private
			// keys, certificates of key
			// pairs, public keys of trusted
			// certificates and keys within
			// key entries of all types
		{
			if (value.toString().equals(res.getString("DProperties.properties.PrivateKey"))) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.PrivateKey.image")));
			} else if (value.toString().equals(res.getString("DProperties.properties.Certificates"))) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.Certificates.image")));
			} else if (value.toString().equals(res.getString("DProperties.properties.PublicKey"))) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.PublicKey.image")));
			} else if (value.toString().equals(res.getString("DProperties.properties.SecretKey"))) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.SecretKey.image")));
			}
			// Otherwise use default icon
			else {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.Default.image")));
			}
		} else if (node.getLevel() == 5) // Sixth level - includes public keys
			// of key pair
			// certificates
		{
			if (value.toString().equals(res.getString("DProperties.properties.PublicKey"))) {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.PublicKey.image")));
			}
			// Otherwise use default icon
			else {
				icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.Default.image")));
			}
		}
		// Otherwise use default icon
		else {
			icon = new ImageIcon(getClass().getResource(res.getString("PropertiesTreeCellRend.Default.image")));
		}

		cell.setIcon(icon);

		return cell;
	}
}
