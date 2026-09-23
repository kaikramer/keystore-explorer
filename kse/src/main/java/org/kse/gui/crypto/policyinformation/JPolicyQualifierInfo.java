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
package org.kse.gui.crypto.policyinformation;

import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.kse.gui.crypto.JAddEditRemovePanel;
import org.kse.gui.table.ToolTipTable;

/**
 * Component to edit a set of policy qualifier info.
 */
public class JPolicyQualifierInfo extends JAddEditRemovePanel<List<PolicyQualifierInfo>, PolicyQualifierInfo> {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/policyinformation/resources");

    private String title;

    /**
     * Construct a JPolicyQualifierInfo.
     *
     * @param title Title of edit dialog
     */
    public JPolicyQualifierInfo(String title) {
        this.title = title;
    }

    @Override
    protected String getAddResource() {
        return "images/add_policy_qualifier_info.png";
    }

    @Override
    protected String getEditResource() {
        return "images/edit_policy_qualifier_info.png";
    }

    @Override
    protected String getRemoveResource() {
        return "images/remove_policy_qualifier_info.png";
    }

    @Override
    protected String getBundleString(String suffix) {
        return res.getString("JPolicyQualifierInfo." + suffix);
    }

    @Override
    protected List<PolicyQualifierInfo> newCollection() {
        return new ArrayList<>();
    }

    @Override
    protected JTable newTable() {
        PolicyQualifierInfoTableModel policyQualifierInfoTableModel = new PolicyQualifierInfoTableModel();
        JTable jtPolicyQualifierInfo = new ToolTipTable(policyQualifierInfoTableModel);

        TableRowSorter<PolicyQualifierInfoTableModel> sorter = new TableRowSorter<>(policyQualifierInfoTableModel);
        sorter.setComparator(0, new PolicyQualifierInfoTableModel.PolicyQualifierInfoComparator());
        jtPolicyQualifierInfo.setRowSorter(sorter);

        jtPolicyQualifierInfo.setShowGrid(false);
        jtPolicyQualifierInfo.setRowMargin(0);
        jtPolicyQualifierInfo.getColumnModel().setColumnMargin(0);
        jtPolicyQualifierInfo.getTableHeader().setReorderingAllowed(false);
        jtPolicyQualifierInfo.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        jtPolicyQualifierInfo.setRowHeight(Math.max(18, jtPolicyQualifierInfo.getRowHeight()));

        for (int i = 0; i < jtPolicyQualifierInfo.getColumnCount(); i++) {
            TableColumn column = jtPolicyQualifierInfo.getColumnModel().getColumn(i);
            column.setCellRenderer(new PolicyQualifierInfoTableCellRend());
        }

        return jtPolicyQualifierInfo;
    }

    @Override
    protected PolicyQualifierInfo getItem(PolicyQualifierInfo item) {
        Container container = getTopLevelAncestor();

        DPolicyQualifierInfoChooser dPolicyQualifierInfoChooser = null;

        if (container instanceof JDialog) {
            dPolicyQualifierInfoChooser = new DPolicyQualifierInfoChooser((JDialog) container, title, item);
        } else {
            dPolicyQualifierInfoChooser = new DPolicyQualifierInfoChooser((JFrame) container, title, item);
        }
        dPolicyQualifierInfoChooser.setLocationRelativeTo(container);
        dPolicyQualifierInfoChooser.setVisible(true);

        return dPolicyQualifierInfoChooser.getPolicyQualifierInfo();
    }
}
