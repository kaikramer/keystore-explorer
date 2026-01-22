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
package org.kse.gui.about;

import net.miginfocom.swing.MigLayout;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.kse.gui.components.JEscDialog;
import org.kse.gui.table.ToolTipTable;
import org.kse.gui.PlatformUtil;

/**
 * A dialog that displays the Environment variables.
 */
public class DEnvironmentVariables extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/about/resources");

    private JButton jbOK;
    private JScrollPane jspEnvironmentVariablesTable;
    private JTable jtEnvironmentVariables;

    /**
     * Creates new DEnvironmentVariables dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     */
    public DEnvironmentVariables(JDialog parent) {
        this(parent, res.getString("DEnvironmentVariables.Title"), ModalityType.DOCUMENT_MODAL);
    }

    /**
     * Creates new DEnvironmentVariables dialog where the parent is a dialog.
     *
     * @param parent   Parent dialog
     * @param title    The title of the dialog
     * @param modality Dialog modality
     */
    public DEnvironmentVariables(JDialog parent, String title, Dialog.ModalityType modality) {
        super(parent, title, modality);
        initComponents();
    }

    private void initComponents() {
        EnvironmentVariablesTableModel evModel = new EnvironmentVariablesTableModel();
        evModel.load();

        jtEnvironmentVariables = new ToolTipTable(evModel);

        jtEnvironmentVariables.setRowMargin(0);
        jtEnvironmentVariables.getColumnModel().setColumnMargin(0);
        jtEnvironmentVariables.getTableHeader().setReorderingAllowed(false);
        jtEnvironmentVariables.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        RowSorter<EnvironmentVariablesTableModel> sorter = new TableRowSorter<>(evModel);
        jtEnvironmentVariables.setRowSorter(sorter);

        for (int i = 0; i < jtEnvironmentVariables.getColumnCount(); i++) {
            TableColumn column = jtEnvironmentVariables.getColumnModel().getColumn(i);

            if (i == 0) {
                column.setPreferredWidth(200);
            } else {
                column.setPreferredWidth(300);
            }

            column.setCellRenderer(new EnvironmentVariablesTableCellRend());
        }

        jspEnvironmentVariablesTable = PlatformUtil.createScrollPane(jtEnvironmentVariables,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspEnvironmentVariablesTable.getViewport().setBackground(jtEnvironmentVariables.getBackground());
        jspEnvironmentVariablesTable.setPreferredSize(new Dimension(500, 300));

        jbOK = new JButton(res.getString("DEnvironmentVariables.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]", "[]"));
        pane.add(jspEnvironmentVariablesTable, "cell 0 0, grow, pushy");
        pane.add(jbOK, "cell 0 1, align right, growx 0");

        setResizable(false);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

    private void okPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}