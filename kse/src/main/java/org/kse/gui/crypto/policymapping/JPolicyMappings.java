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
package org.kse.gui.crypto.policymapping;

import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.kse.crypto.x509.PolicyMapping;
import org.kse.crypto.x509.PolicyMappingsUtil;
import org.kse.gui.crypto.JAddEditRemovePanel;
import org.kse.gui.table.ToolTipTable;

/**
 * Component to edit a set of policy mappings.
 */
public class JPolicyMappings extends JAddEditRemovePanel<List<PolicyMapping>, PolicyMapping> {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/policymapping/resources");

    private String title;

    /**
     * Construct a JPolicyMappings.
     *
     * @param title Title of edit dialog
     */
    public JPolicyMappings(String title) {
        this.title = title;
    }

    @Override
    protected String getAddResource() {
        return "images/add_policy_map.png";
    }

    @Override
    protected String getEditResource() {
        return "images/edit_policy_map.png";
    }

    @Override
    protected String getRemoveResource() {
        return "images/remove_policy_map.png";
    }

    @Override
    protected String getBundleString(String suffix) {
        return res.getString("JPolicyMappings." + suffix);
    }

    @Override
    protected List<PolicyMapping> newCollection() {
        return new ArrayList<>();
    }

    @Override
    protected JTable newTable() {
        PolicyMappingsTableModel policyMappingsTableModel = new PolicyMappingsTableModel();
        JTable jtPolicyMappings = new ToolTipTable(policyMappingsTableModel);

        TableRowSorter<PolicyMappingsTableModel> sorter = new TableRowSorter<>(policyMappingsTableModel);
        sorter.setComparator(0, new PolicyMappingsTableModel.IssuerDomainPolicyComparator());
        sorter.setComparator(1, new PolicyMappingsTableModel.SubjectDomainPolicyComparator());
        jtPolicyMappings.setRowSorter(sorter);

        jtPolicyMappings.setShowGrid(false);
        jtPolicyMappings.setRowMargin(0);
        jtPolicyMappings.getColumnModel().setColumnMargin(0);
        jtPolicyMappings.getTableHeader().setReorderingAllowed(false);
        jtPolicyMappings.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        jtPolicyMappings.setRowHeight(Math.max(18, jtPolicyMappings.getRowHeight()));

        for (int i = 0; i < jtPolicyMappings.getColumnCount(); i++) {
            TableColumn column = jtPolicyMappings.getColumnModel().getColumn(i);
            column.setCellRenderer(new PolicyMappingsTableCellRend());
        }

        return jtPolicyMappings;
    }

    @Override
    protected PolicyMapping getItem(PolicyMapping item) {
        Container container = getTopLevelAncestor();

        DPolicyMappingChooser dPolicyMappingChooser = null;

        if (container instanceof JDialog) {
            dPolicyMappingChooser = new DPolicyMappingChooser((JDialog) container, title, item);
        } else {
            dPolicyMappingChooser = new DPolicyMappingChooser((JFrame) container, title, item);
        }
        dPolicyMappingChooser.setLocationRelativeTo(container);
        dPolicyMappingChooser.setVisible(true);

        return dPolicyMappingChooser.getPolicyMapping();
    }

    /**
     * Get policy mappings.
     *
     * @return Policy mappings
     */
    public PolicyMappings getPolicyMappings() {
        return PolicyMappingsUtil.createFromList(getItems());
    }

    /**
     * Set policy mappings.
     *
     * @param policyMappings Policy mappings
     */
    public void setPolicyMappings(PolicyMappings policyMappings) {
        ASN1Sequence policyMappingsSeq = (ASN1Sequence) policyMappings.toASN1Primitive();

        // convert and sort
        ASN1Encodable[] asn1EncArray = policyMappingsSeq.toArray();
        List<PolicyMapping> policyMappingsArray = new ArrayList<>();
        for (int i = 0; i < asn1EncArray.length; i++) {
            policyMappingsArray.add(PolicyMapping.getInstance(asn1EncArray[i]));
        }

        setItems(policyMappingsArray);
    }

}
