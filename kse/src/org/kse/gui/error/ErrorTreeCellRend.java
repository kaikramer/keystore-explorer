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
package org.kse.gui.error;

import java.awt.Component;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;

/**
 * Custom cell renderer for the cells of the DErrorDetail tree.
 *
 */
public class ErrorTreeCellRend extends DefaultTreeCellRenderer {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/error/resources");

	/**
	 * Returns the rendered cell for the supplied value.
	 *
	 * @param jtrError
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
	public Component getTreeCellRendererComponent(JTree jtrError, Object value, boolean isSelected, boolean isExpanded,
			boolean leaf, int row, boolean hasFocus) {
		JLabel cell = (JLabel) super.getTreeCellRendererComponent(jtrError, value, isSelected, isExpanded, leaf, row,
				hasFocus);
		cell.setText(value.toString());

		DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
		Object userValue = node.getUserObject();
		ImageIcon icon = null;

		if (userValue instanceof Throwable) {
			icon = new ImageIcon(getClass().getResource(res.getString("ErrorTreeCellRend.Error.image")));
			cell.setToolTipText(res.getString("ErrorTreeCellRend.Error.tooltip"));
		} else if (userValue instanceof StackTraceElement) {
			icon = new ImageIcon(getClass().getResource(res.getString("ErrorTreeCellRend.StackTrace.image")));
			cell.setToolTipText(res.getString("ErrorTreeCellRend.StackTrace.tooltip"));
		} else {
			icon = new ImageIcon(getClass().getResource(res.getString("ErrorTreeCellRend.Root.image")));
			cell.setToolTipText(res.getString("ErrorTreeCellRend.Root.tooltip"));
		}

		cell.setIcon(icon);

		return cell;
	}
}
