/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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
package org.kse.gui.crypto.generalsubtree;

import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.kse.crypto.x509.GeneralSubtrees;
import org.kse.gui.crypto.JAddEditRemovePanel;
import org.kse.gui.table.ToolTipTable;

/**
 * Component to edit a set of general subtrees.
 */
public class JGeneralSubtrees extends JAddEditRemovePanel<List<GeneralSubtree>, GeneralSubtree> {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/generalsubtree/resources");

    private String title;

    /**
     * Construct a JGeneralSubtrees.
     *
     * @param title Title of edit dialog
     */
    public JGeneralSubtrees(String title) {
        this.title = title;
    }

    @Override
    protected String getAddResource() {
        return "images/add_general_subtree.png";
    }

    @Override
    protected String getEditResource() {
        return "images/edit_general_subtree.png";
    }

    @Override
    protected String getRemoveResource() {
        return "images/remove_general_subtree.png";
    }

    @Override
    protected String getBundleString(String suffix) {
        return res.getString("JGeneralSubtrees." + suffix);
    }

    @Override
    protected List<GeneralSubtree> newCollection() {
        return new ArrayList<>();
    }

    @Override
    protected JTable newTable() {
        GeneralSubtreesTableModel generalSubtreesTableModel = new GeneralSubtreesTableModel();
        JTable jtGeneralSubtrees = new ToolTipTable(generalSubtreesTableModel);

        TableRowSorter<GeneralSubtreesTableModel> sorter = new TableRowSorter<>(generalSubtreesTableModel);
        sorter.setComparator(0, new GeneralSubtreesTableModel.GeneralSubtreeBaseComparator());
        sorter.setComparator(1, new GeneralSubtreesTableModel.GeneralSubtreeMinimumComparator());
        sorter.setComparator(2, new GeneralSubtreesTableModel.GeneralSubtreeMaximumComparator());
        jtGeneralSubtrees.setRowSorter(sorter);

        jtGeneralSubtrees.setShowGrid(false);
        jtGeneralSubtrees.setRowMargin(0);
        jtGeneralSubtrees.getColumnModel().setColumnMargin(0);
        jtGeneralSubtrees.getTableHeader().setReorderingAllowed(false);
        jtGeneralSubtrees.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        jtGeneralSubtrees.setRowHeight(Math.max(18, jtGeneralSubtrees.getRowHeight()));

        for (int i = 0; i < jtGeneralSubtrees.getColumnCount(); i++) {
            TableColumn column = jtGeneralSubtrees.getColumnModel().getColumn(i);
            column.setCellRenderer(new GeneralSubtreesTableCellRend());
        }

        return jtGeneralSubtrees;
    }

    @Override
    protected GeneralSubtree getItem(GeneralSubtree item) {
        Container container = getTopLevelAncestor();

        DGeneralSubtreeChooser dGeneralSubtreeChooser = null;

        if (container instanceof JDialog) {
            dGeneralSubtreeChooser = new DGeneralSubtreeChooser((JDialog) container, title, item);
        } else {
            dGeneralSubtreeChooser = new DGeneralSubtreeChooser((JFrame) container, title, item);
        }
        dGeneralSubtreeChooser.setLocationRelativeTo(container);
        dGeneralSubtreeChooser.setVisible(true);

        return dGeneralSubtreeChooser.getGeneralSubtree();
    }

    /**
     * Get general subtrees.
     *
     * @return General subtrees
     */
    public GeneralSubtrees getGeneralSubtrees() {
        return new GeneralSubtrees(getItems());
    }

    /**
     * Set general subtrees.
     *
     * @param generalSubtrees General subtrees
     */
    public void setGeneralSubtrees(GeneralSubtrees generalSubtrees) {
        setItems(new ArrayList<>(generalSubtrees.getGeneralSubtrees()));
    }
}
