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
package org.kse.gui.crypto.customextkeyusage;

import java.awt.Container;
import java.util.HashSet;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.gui.crypto.JAddEditRemovePanel;
import org.kse.gui.error.DError;
import org.kse.gui.oid.DObjectIdChooser;
import org.kse.gui.table.ToolTipTable;
import org.kse.utilities.oid.InvalidObjectIdException;
import org.kse.utilities.oid.ObjectIdComparator;

/**
 * Component to edit a set of custom extended key usages.
 */
public class JCustomExtendedKeyUsage extends JAddEditRemovePanel<Set<ASN1ObjectIdentifier>, ASN1ObjectIdentifier> {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/customextkeyusage/resources");

    private String title;

    /**
     * Construct a JCustomExtKeyUsage.
     *
     * @param title Title of edit dialog
     */
    public JCustomExtendedKeyUsage(String title) {
        this.title = title;
    }

    @Override
    protected String getAddResource() {
        return "images/add_custom_eku.png";
    }

    @Override
    protected String getEditResource() {
        return "images/edit_custom_eku.png";
    }

    @Override
    protected String getRemoveResource() {
        return "images/remove_custom_eku.png";
    }

    @Override
    protected String getBundleString(String suffix) {
        return res.getString("JCustomExtKeyUsage." + suffix);
    }

    @Override
    protected Set<ASN1ObjectIdentifier> newCollection() {
        return new HashSet<>();
    }

    @Override
    protected JTable newTable() {
        CustomExtKeyUsageTableModel customExtKeyUsageTableModel = new CustomExtKeyUsageTableModel();
        JTable jtCustomExtKeyUsages = new ToolTipTable(customExtKeyUsageTableModel);

        TableRowSorter<CustomExtKeyUsageTableModel> sorter = new TableRowSorter<>(customExtKeyUsageTableModel);
        sorter.setComparator(0, new ObjectIdComparator());
        jtCustomExtKeyUsages.setRowSorter(sorter);

        jtCustomExtKeyUsages.setShowGrid(false);
        jtCustomExtKeyUsages.setRowMargin(0);
        jtCustomExtKeyUsages.getColumnModel().setColumnMargin(0);
        jtCustomExtKeyUsages.getTableHeader().setReorderingAllowed(false);
        jtCustomExtKeyUsages.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        jtCustomExtKeyUsages.setRowHeight(Math.max(18, jtCustomExtKeyUsages.getRowHeight()));

        for (int i = 0; i < jtCustomExtKeyUsages.getColumnCount(); i++) {
            TableColumn column = jtCustomExtKeyUsages.getColumnModel().getColumn(i);
            column.setCellRenderer(new CustomExtKeyUsageTableCellRend());
        }

        return jtCustomExtKeyUsages;
    }

    @Override
    protected ASN1ObjectIdentifier getItem(ASN1ObjectIdentifier item) {
        Container container = getTopLevelAncestor();

        try {
            DObjectIdChooser dObjectIdChooser = null;
            if (container instanceof JDialog) {
                dObjectIdChooser = new DObjectIdChooser((JDialog) container, title, item);
            } else {
                dObjectIdChooser = new DObjectIdChooser((JFrame) container, title, item);
            }

            dObjectIdChooser.setLocationRelativeTo(container);
            dObjectIdChooser.setVisible(true);

            return dObjectIdChooser.getObjectId();

        } catch (InvalidObjectIdException ex) {
            DError dError = null;

            if (container instanceof JDialog) {
                dError = new DError((JDialog) container, ex);
            } else {
                dError = new DError((JFrame) container, ex);
            }

            dError.setLocationRelativeTo(container);
            dError.setVisible(true);

            return null;
        }
    }

}
