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

package org.kse.gui.crypto.distributionpoints;

import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.x509.DistributionPoint;
import org.kse.gui.crypto.JAddEditRemovePanel;
import org.kse.gui.table.ToolTipTable;

/**
 * Component to show the list distribution points.
 */
public class JDistributionPoints extends JAddEditRemovePanel<List<DistributionPoint>, DistributionPoint> {

    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/distributionpoints/resources");

    private String title;

    /**
     * Creates a new JDistributionPoints
     *
     * @param title The title of the window.
     */
    public JDistributionPoints(String title) {
        this.title = title;
    }

    @Override
    protected String getAddResource() {
        return "images/add_distribution_nms.png";
    }

    @Override
    protected String getEditResource() {
        return "images/edit_distribution_nms.png";
    }

    @Override
    protected String getRemoveResource() {
        return "images/remove_distribution_nms.png";
    }

    @Override
    protected String getBundleString(String suffix) {
        return res.getString("JDistributionPoints." + suffix);
    }

    @Override
    protected List<DistributionPoint> newCollection() {
        return new ArrayList<>();
    }

    @Override
    protected JTable newTable() {
        DistributionPointsTableModel distributionPointsTableModel = new DistributionPointsTableModel();
        JTable jtDistributionPoints = new ToolTipTable(distributionPointsTableModel);

        TableRowSorter<DistributionPointsTableModel> sorter = new TableRowSorter<>(distributionPointsTableModel);
        sorter.setComparator(0, new DistributionPointsTableModel.DistributionPointComparator());
        jtDistributionPoints.setRowSorter(sorter);

        jtDistributionPoints.setShowGrid(false);
        jtDistributionPoints.setRowMargin(0);
        jtDistributionPoints.getColumnModel().setColumnMargin(0);
        jtDistributionPoints.getTableHeader().setReorderingAllowed(false);
        jtDistributionPoints.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        jtDistributionPoints.setRowHeight(Math.max(18, jtDistributionPoints.getRowHeight()));

        for (int i = 0; i < jtDistributionPoints.getColumnCount(); i++) {
            TableColumn column = jtDistributionPoints.getColumnModel().getColumn(i);
            column.setCellRenderer(new DistributionPointsTableCellRend());
        }

        return jtDistributionPoints;
    }

    @Override
    protected DistributionPoint getItem(DistributionPoint item) {
        Container container = getTopLevelAncestor();

        DDistributionPointsChooser distributionPointsChooser = null;

        if (container instanceof JDialog) {
            distributionPointsChooser = new DDistributionPointsChooser((JDialog) container, title, item);
        } else {
            distributionPointsChooser = new DDistributionPointsChooser((JFrame) container, title, item);
        }

        distributionPointsChooser.setLocationRelativeTo(container);
        distributionPointsChooser.setVisible(true);

        return distributionPointsChooser.getDistributionPoint();
    }

}
