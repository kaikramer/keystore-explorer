/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

package org.kse.gui.preferences;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.font.FontRenderContext;
import java.awt.geom.AffineTransform;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;

/**
 * Renderer class to populate and style tree cells
 */
class SettingsTreeCellRenderer extends DefaultTreeCellRenderer {

    private static final long serialVersionUID = -4925141688439747036L;

    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf,
                                                  int row, boolean hasFocus) {

        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
        int iconPadding = 10; // add padding to icon width
        int heightPadding = 8; // add padding to height
        AffineTransform affinetransform = new AffineTransform();
        FontRenderContext frc = new FontRenderContext(affinetransform, true, true);

        if (node.isLeaf()) {
            MenuTreeNode menuTreeNode = (MenuTreeNode) node.getUserObject();
            int textWidth = (int) (getFont().getStringBounds(menuTreeNode.getName(), frc).getWidth());
            int textHeight = (int) (getFont().getStringBounds(menuTreeNode.getName(), frc).getHeight());
            Dimension d = new Dimension(menuTreeNode.getLabelIcon().getIconWidth() + iconPadding + textWidth,
                                        heightPadding + textHeight);
            setPreferredSize(d); // set cell preferred size
            setText(menuTreeNode.getName());
            setIcon(menuTreeNode.getLabelIcon());
            setToolTipText(menuTreeNode.getToolTip());
        } else {
            setLeafIcon(null);
            setClosedIcon(null);
            setOpenIcon(null);
        }

        return this;
    }
}
