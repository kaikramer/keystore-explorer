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

import java.util.ResourceBundle;

import javax.swing.ImageIcon;

/**
 * MenuTreeNode class to compile a set of items used for tree nodes
 */
class MenuTreeNode {
    private ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");

    private String name;
    private ImageIcon icon;
    private String tooltip;
    private String card;

    public MenuTreeNode(String name, String icon, String tooltip, String card) {
        super();
        this.name = res.getString(name);
        this.icon = new ImageIcon(this.getClass().getResource(icon));
        this.tooltip = res.getString(tooltip);
        this.card = card;
    }

    public MenuTreeNode() {
        super();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = res.getString(name);
    }

    public ImageIcon getLabelIcon() {
        return icon;
    }

    public void setLabelIcon(String icon) {
        this.icon = new ImageIcon(this.getClass().getResource(icon));
    }

    public String getToolTip() {
        return tooltip;
    }

    public void setToolTip(String tooltip) {
        this.tooltip = res.getString(tooltip);
    }

    public String getCard() {
        return card;
    }

    public void setCard(String card) {
        this.card = card;
    }
}
