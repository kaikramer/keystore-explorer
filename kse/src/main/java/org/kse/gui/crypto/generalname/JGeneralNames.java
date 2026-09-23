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
package org.kse.gui.crypto.generalname;

import java.awt.Container;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.kse.gui.crypto.JAddEditRemovePanel;
import org.kse.gui.table.ToolTipTable;

/**
 * Component to edit a set of general names.
 */
public class JGeneralNames extends JAddEditRemovePanel<List<GeneralName>, GeneralName> {
    private static final long serialVersionUID = 459512931464920941L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/generalname/resources");

    private String title;

    /**
     * Construct a JGeneralNames.
     *
     * @param title Title of edit dialog
     */
    public JGeneralNames(String title) {
        this.title = title;
    }

    @Override
    protected String getAddResource() {
        return "images/add_general_nms.png";
    }

    @Override
    protected String getEditResource() {
        return "images/edit_general_nms.png";
    }

    @Override
    protected String getRemoveResource() {
        return "images/remove_general_nms.png";
    }

    @Override
    protected String getBundleString(String suffix) {
        return res.getString("JGeneralNames." + suffix);
    }

    @Override
    protected List<GeneralName> newCollection() {
        return new ArrayList<>();
    }

    @Override
    protected JTable newTable() {
        GeneralNamesTableModel generalNamesTableModel = new GeneralNamesTableModel();
        JTable jtGeneralNames = new ToolTipTable(generalNamesTableModel);

        TableRowSorter<GeneralNamesTableModel> sorter = new TableRowSorter<>(generalNamesTableModel);
        sorter.setComparator(0, new GeneralNamesTableModel.GeneralNameComparator());
        jtGeneralNames.setRowSorter(sorter);

        jtGeneralNames.setShowGrid(false);
        jtGeneralNames.setRowMargin(0);
        jtGeneralNames.getColumnModel().setColumnMargin(0);
        jtGeneralNames.getTableHeader().setReorderingAllowed(false);
        jtGeneralNames.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        jtGeneralNames.setRowHeight(Math.max(18, jtGeneralNames.getRowHeight()));

        for (int i = 0; i < jtGeneralNames.getColumnCount(); i++) {
            TableColumn column = jtGeneralNames.getColumnModel().getColumn(i);
            column.setCellRenderer(new GeneralNamesTableCellRend());
        }

        return jtGeneralNames;
    }

    @Override
    protected GeneralName getItem(GeneralName item) {
        Container container = getTopLevelAncestor();

        DGeneralNameChooser dGeneralNameChooser = null;

        if (container instanceof JDialog) {
            dGeneralNameChooser = new DGeneralNameChooser((JDialog) container, title, item);
        } else {
            dGeneralNameChooser = new DGeneralNameChooser((JFrame) container, title, item);
        }
        dGeneralNameChooser.setLocationRelativeTo(container);
        dGeneralNameChooser.setVisible(true);

        return dGeneralNameChooser.getGeneralName();
    }

    /**
     * Get general names.
     *
     * @return General names
     */
    public GeneralNames getGeneralNames() {
        return new GeneralNames(getItems().toArray(GeneralName[]::new));
    }

    /**
     * Set general names.
     *
     * @param generalNames General names
     */
    public void setGeneralNames(GeneralNames generalNames) {
        setItems(new ArrayList<>(Arrays.asList(generalNames.getNames())));
    }
}
