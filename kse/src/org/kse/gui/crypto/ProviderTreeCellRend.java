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
package org.kse.gui.crypto;

import java.awt.Component;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeNode;

/**
 * Custom cell renderer for the cells of the DProviderInfo tree.
 *
 */
public class ProviderTreeCellRend extends DefaultTreeCellRenderer {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

	/**
	 * Returns the rendered cell for the supplied value.
	 *
	 * @param jtrProvider
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
	public Component getTreeCellRendererComponent(JTree jtrProvider, Object value, boolean isSelected,
			boolean isExpanded, boolean leaf, int row, boolean hasFocus) {
		JLabel cell = (JLabel) super.getTreeCellRendererComponent(jtrProvider, value, isSelected, isExpanded, leaf,
				row, hasFocus);
		cell.setText(value.toString());

		// Get the correct icon for the node
		DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;

		ImageIcon icon = null;

		if (node.getLevel() == 0) // First level - root
		{
			// Root node
			icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Root.image")));
			cell.setToolTipText(res.getString("ProviderTreeCellRend.Root.tooltip"));
		} else if (node.getLevel() == 1) // Second level - providers
		{
			// Provider node - name and version
			icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Provider.image")));
			cell.setToolTipText(res.getString("ProviderTreeCellRend.Provider.tooltip"));
		} else if (node.getLevel() == 2) // Third level - provider description,
			// version, java class
			// and services
		{
			TreeNode parent = node.getParent();
			int index = parent.getIndex(node);

			if (index == 0) {
				// Provider description node
				icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Description.image")));
				cell.setToolTipText(res.getString("ProviderTreeCellRend.Description.tooltip"));
			} else if (index == 1) {
				// Provider class node
				icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.ProviderClass.image")));
				cell.setToolTipText(res.getString("ProviderTreeCellRend.ProviderClass.tooltip"));
			} else {
				// Provider services node
				icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Services.image")));
				cell.setToolTipText(res.getString("ProviderTreeCellRend.Services.tooltip"));
			}
		} else if (node.getLevel() == 3) // Fourth level - list if services
		{
			// Provider service node
			icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Service.image")));
			cell.setToolTipText(res.getString("ProviderTreeCellRend.Service.tooltip"));
		} else if (node.getLevel() == 4) // Fifth level - list of service
			// algorithms
		{
			// Service algorithm node
			icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Algorithm.image")));
			cell.setToolTipText(res.getString("ProviderTreeCellRend.Algorithm.tooltip"));
		} else if (node.getLevel() == 5) // Sixth level - algorithm java class,
			// attributes and aliases
		{
			TreeNode parent = node.getParent();
			int index = parent.getIndex(node);

			if (index == 0) {
				// Algorithm class node
				icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.AlgorithmClass.image")));
				cell.setToolTipText(res.getString("ProviderTreeCellRend.AlgorithmClass.tooltip"));
			} else if (node.toString().equals(res.getString("DProviderInfo.AttributesNode.text"))) {
				// Algorithm attributes node
				icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Attributes.image")));
				cell.setToolTipText(res.getString("ProviderTreeCellRend.Attributes.tooltip"));
			} else {
				// Algorithm aliases node
				icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Aliases.image")));
				cell.setToolTipText(res.getString("ProviderTreeCellRend.Aliases.tooltip"));
			}
		} else
			// Seventh level - list of attributes or aliases
		{
			TreeNode parent = node.getParent();

			if (parent.toString().equals(res.getString("DProviderInfo.AttributesNode.text"))) {
				// Algorithm attribute node
				icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Attribute.image")));
				cell.setToolTipText(res.getString("ProviderTreeCellRend.Attribute.tooltip"));
			} else {
				// Algorithm alias node
				icon = new ImageIcon(getClass().getResource(res.getString("ProviderTreeCellRend.Alias.image")));
				cell.setToolTipText(res.getString("ProviderTreeCellRend.Alias.tooltip"));
			}
		}

		cell.setIcon(icon);

		return cell;
	}
}
