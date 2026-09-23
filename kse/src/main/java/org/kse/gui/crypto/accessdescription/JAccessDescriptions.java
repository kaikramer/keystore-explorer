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
package org.kse.gui.crypto.accessdescription;

import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.x509.AccessDescription;
import org.kse.gui.crypto.JAddEditRemovePanel;
import org.kse.gui.table.ToolTipTable;

/**
 * Component to edit a set of access descriptions.
 */
public class JAccessDescriptions extends JAddEditRemovePanel<List<AccessDescription>, AccessDescription> {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/accessdescription/resources");

    private String title;

    /**
     * Construct a JAccessDescriptions.
     *
     * @param title Title of edit dialog
     */
    public JAccessDescriptions(String title) {
        this.title = title;
    }

    @Override
    protected String getAddResource() {
        return "images/add_access_desc.png";
    }

    @Override
    protected String getEditResource() {
        return "images/edit_access_desc.png";
    }

    @Override
    protected String getRemoveResource() {
        return "images/remove_access_desc.png";
    }

    @Override
    protected String getBundleString(String suffix) {
        return res.getString("JAccessDescriptions." + suffix);
    }

    @Override
    protected List<AccessDescription> newCollection() {
        return new ArrayList<>();
    }

    @Override
    protected JTable newTable() {
        AccessDescriptionsTableModel accessDescriptionsTableModel = new AccessDescriptionsTableModel();
        JTable jtAccessDescriptions = new ToolTipTable(accessDescriptionsTableModel);

        TableRowSorter<AccessDescriptionsTableModel> sorter = new TableRowSorter<>(accessDescriptionsTableModel);
        sorter.setComparator(0, new AccessDescriptionsTableModel.AccessDescriptionMethodComparator());
        sorter.setComparator(1, new AccessDescriptionsTableModel.AccessDescriptionLocationComparator());
        jtAccessDescriptions.setRowSorter(sorter);

        jtAccessDescriptions.setShowGrid(false);
        jtAccessDescriptions.setRowMargin(0);
        jtAccessDescriptions.getColumnModel().setColumnMargin(0);
        jtAccessDescriptions.getTableHeader().setReorderingAllowed(false);
        jtAccessDescriptions.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        jtAccessDescriptions.setRowHeight(Math.max(18, jtAccessDescriptions.getRowHeight()));

        for (int i = 0; i < jtAccessDescriptions.getColumnCount(); i++) {
            TableColumn column = jtAccessDescriptions.getColumnModel().getColumn(i);
            column.setCellRenderer(new AccessDescriptionsTableCellRend());
        }

        return jtAccessDescriptions;
    }

    @Override
    protected AccessDescription getItem(AccessDescription item) {
        DAccessDescriptionChooser dAccessDescriptionChooser = null;

        Container container = getTopLevelAncestor();

        if (container instanceof JDialog) {
            dAccessDescriptionChooser = new DAccessDescriptionChooser((JDialog) container, title, item);
        } else {
            dAccessDescriptionChooser = new DAccessDescriptionChooser((JFrame) container, title, item);
        }
        dAccessDescriptionChooser.setLocationRelativeTo(container);
        dAccessDescriptionChooser.setVisible(true);

        return dAccessDescriptionChooser.getAccessDescription();
    }

}
