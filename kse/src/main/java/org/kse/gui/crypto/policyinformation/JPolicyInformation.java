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

import org.bouncycastle.asn1.x509.PolicyInformation;
import org.kse.gui.crypto.JAddEditRemovePanel;
import org.kse.gui.table.ToolTipTable;

/**
 * Component to edit a set of policy information.
 */
public class JPolicyInformation extends JAddEditRemovePanel<List<PolicyInformation>, PolicyInformation> {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/policyinformation/resources");

    private String title;

    /**
     * Construct a JPolicyInformation.
     *
     * @param title Title of edit dialog
     */
    public JPolicyInformation(String title) {
        this.title = title;
    }

    @Override
    protected String getAddResource() {
        return "images/add_policy_info.png";
    }

    @Override
    protected String getEditResource() {
        return "images/edit_policy_info.png";
    }

    @Override
    protected String getRemoveResource() {
        return "images/remove_policy_info.png";
    }

    @Override
    protected String getBundleString(String suffix) {
        return res.getString("JPolicyInformation." + suffix);
    }

    @Override
    protected List<PolicyInformation> newCollection() {
        return new ArrayList<>();
    }

    @Override
    protected JTable newTable() {
        PolicyInformationTableModel policyInformationTableModel = new PolicyInformationTableModel();
        JTable jtPolicyInformation = new ToolTipTable(policyInformationTableModel);

        TableRowSorter<PolicyInformationTableModel> sorter = new TableRowSorter<>(policyInformationTableModel);
        sorter.setComparator(0, new PolicyInformationTableModel.PolicyInformationComparator());
        jtPolicyInformation.setRowSorter(sorter);

        jtPolicyInformation.setShowGrid(false);
        jtPolicyInformation.setRowMargin(0);
        jtPolicyInformation.getColumnModel().setColumnMargin(0);
        jtPolicyInformation.getTableHeader().setReorderingAllowed(false);
        jtPolicyInformation.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        jtPolicyInformation.setRowHeight(Math.max(18, jtPolicyInformation.getRowHeight()));

        for (int i = 0; i < jtPolicyInformation.getColumnCount(); i++) {
            TableColumn column = jtPolicyInformation.getColumnModel().getColumn(i);
            column.setCellRenderer(new PolicyInformationTableCellRend());
        }

        return jtPolicyInformation;
    }

    @Override
    protected PolicyInformation getItem(PolicyInformation item) {
        Container container = getTopLevelAncestor();

        DPolicyInformationChooser dPolicyInformationChooser = null;

        if (container instanceof JDialog) {
            dPolicyInformationChooser = new DPolicyInformationChooser((JDialog) container, title, item);
        } else {
            dPolicyInformationChooser = new DPolicyInformationChooser((JFrame) container, title, item);
        }
        dPolicyInformationChooser.setLocationRelativeTo(container);
        dPolicyInformationChooser.setVisible(true);

        return dPolicyInformationChooser.getPolicyInformation();
    }
}
