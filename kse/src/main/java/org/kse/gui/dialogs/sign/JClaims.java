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

package org.kse.gui.dialogs.sign;

import java.awt.Dimension;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.kse.gui.crypto.JAddEditRemovePanel;
import org.kse.gui.table.ToolTipTable;

/**
 * Component to show the list of custom claims
 */
public class JClaims extends JAddEditRemovePanel<List<CustomClaim>, CustomClaim> {

    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

    private JFrame parent;

    /**
     * Creates a new JClaims
     *
     * @param parent The parent frame
     */
    public JClaims(JFrame parent) {
        super();
        this.parent = parent;
        initComponents();
    }

    @Override
    protected String getAddResource() {
        return "images/add_claim_nms.png";
    }

    @Override
    protected String getEditResource() {
        return "images/edit_claim_nms.png";
    }

    @Override
    protected String getRemoveResource() {
        return "images/remove_claim_nms.png";
    }

    @Override
    protected String getBundleString(String suffix) {
        return res.getString("JClaims." + suffix);
    }

    @Override
    protected List<CustomClaim> newCollection() {
        return new ArrayList<>();
    }

    @Override
    protected JTable newTable() {
        ListClaimsTableModel rcModel = new ListClaimsTableModel();
        JTable jtClaims = new ToolTipTable(rcModel);

        TableRowSorter<ListClaimsTableModel> sorter = new TableRowSorter<>(rcModel);
        sorter.setComparator(0, new ListClaimsTableModel.CustomClaimNameComparator());
        sorter.setComparator(1, new ListClaimsTableModel.CustomClaimValueComparator());
        jtClaims.setRowSorter(sorter);

        jtClaims.setShowGrid(false);
        jtClaims.setRowMargin(0);
        jtClaims.getColumnModel().setColumnMargin(0);
        jtClaims.getTableHeader().setReorderingAllowed(false);
        jtClaims.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        jtClaims.setRowHeight(Math.max(18, jtClaims.getRowHeight()));

        for (int i = 0; i < jtClaims.getColumnCount(); i++) {
            TableColumn column = jtClaims.getColumnModel().getColumn(i);

            if (i == 0) {
                column.setPreferredWidth(100);
            }

            column.setCellRenderer(new ClaimsTableCellRend());
        }

        return jtClaims;
    }

    @Override
    protected CustomClaim getItem(CustomClaim item) {
        String name = "";
        String value = "";

        if (item != null) {
            name = item.getName();
            value = item.getValue();
        }

        DCustomClaim dialog = new DCustomClaim(parent, name, value);
        dialog.setLocationRelativeTo(parent);
        dialog.setVisible(true);

        if (dialog.isOk()) {
            return new CustomClaim(dialog.getClaimName(), dialog.getClaimValue());
        }

        return null;
    }

    private void initComponents() {
        // Override the default preferred size with one that fits
        // better with DSignJwt.
        setPreferredSize(new Dimension(50, 150));
    }
}
