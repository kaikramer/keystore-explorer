/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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
public class Pkcs12InfoTreeCellRend extends DefaultTreeCellRenderer {
    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    /**
     * Returns the rendered cell for the supplied value.
     *
     * @param jtrProperties The JTree
     * @param value The value to assign to the cell
     * @param isSelected True if cell is selected
     * @param isExpanded True if cell is expanded
     * @param leaf True if cell is a leaf
     * @param row The row of the cell to render
     * @param hasFocus If true, render cell appropriately
     * @return The rendered cell
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

        if (node.getLevel() == 1) {
            TreeNode parent = node.getParent();
            int index = parent.getIndex(node);

            if (index == 0) {
                icon = new ImageIcon(getClass().getResource("images/file_node.png"));
            } else if (index == 1) {
                icon = new ImageIcon(getClass().getResource("images/type_node.png"));
            } else if (value.toString().contains("MAC")) {
                icon = new ImageIcon(getClass().getResource("images/mac.png"));
            } else if (value.toString().contains("PKCS#7 Data")) {
                icon = new ImageIcon(getClass().getResource("images/data.png"));
            } else if (value.toString().contains("PKCS#7 Encrypted Data")) {
                icon = new ImageIcon(getClass().getResource("images/encr_data.png"));
            } else {
                icon = new ImageIcon(getClass().getResource("images/entry_node.png"));
            }
        } else {

            if (value.toString().contains("Certificate Bag")) {
                icon = new ImageIcon(getClass().getResource("images/certificates_node.png"));
            } else if (value.toString().contains("Key Bag")) {
                icon = new ImageIcon(getClass().getResource("images/privatekey_node.png"));
            } else if (value.toString().contains("Bag Attributes")) {
                icon = new ImageIcon(getClass().getResource("images/bag_attributes.png"));
            } else {
                icon = new ImageIcon(getClass().getResource("images/default_node.png"));
            }
        }

        cell.setIcon(icon);
        return cell;
    }
}
