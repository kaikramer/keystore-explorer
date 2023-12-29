/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;

/**
 * Component to show the list of custom claims
 */
public class JClaims extends JPanel {

    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

    private JFrame parent;
    private JLabel jlClaims;
    private JScrollPane jspClaimsTable;
    private JKseTable jtClaims;

    private JPanel jpClaimsButtons;
    private JButton jbAdd;
    private JButton jbEdit;
    private JButton jbRemove;

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

    private void initComponents() {

        jbAdd = new JButton(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/add_claim_nms.png"))));
        jbAdd.setMargin(new Insets(2, 2, 0, 0));
        jbAdd.setToolTipText(res.getString("JClaims.jbAdd.tooltip"));
        jbAdd.setMnemonic(res.getString("JClaims.jbAdd.mnemonic").charAt(0));

        jbAdd.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JClaims.this);
                addPressed();
            } finally {
                CursorUtil.setCursorFree(JClaims.this);
            }
        });

        jbEdit = new JButton(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/edit_claim_nms.png"))));
        jbEdit.setMargin(new Insets(2, 2, 0, 0));
        jbEdit.setToolTipText(res.getString("JClaims.jbEdit.tooltip"));
        jbEdit.setMnemonic(res.getString("JClaims.jbEdit.mnemonic").charAt(0));

        jbEdit.setEnabled(false);

        jbEdit.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JClaims.this);
                editPressed();
            } finally {
                CursorUtil.setCursorFree(JClaims.this);
            }
        });

        jbRemove = new JButton(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/remove_claim_nms.png"))));
        jbRemove.setMargin(new Insets(2, 2, 0, 0));
        jbRemove.setToolTipText(res.getString("JClaims.jbRemove.tooltip"));
        jbRemove.setMnemonic(res.getString("JClaims.jbRemove.mnemonic").charAt(0));

        jbRemove.setEnabled(false);

        jbRemove.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JClaims.this);
                removePressed();
            } finally {
                CursorUtil.setCursorFree(JClaims.this);
            }
        });

        jlClaims = new JLabel(res.getString("JClaims.jlClaims.text"));
        ListClaimsTableModel rcModel = new ListClaimsTableModel();

        jtClaims = new JKseTable(rcModel);
        ListSelectionModel selectionModel = jtClaims.getSelectionModel();
        selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        selectionModel.addListSelectionListener(evt -> {
            if (!evt.getValueIsAdjusting()) {
                updateButtonControls();
            }
        });
        jtClaims.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent evt) {
                maybeEditClaim(evt);
            }
        });
        RowSorter<ListClaimsTableModel> sorter = new TableRowSorter<>(rcModel);
        jtClaims.setRowSorter(sorter);

        jtClaims.setShowGrid(false);
        jtClaims.setRowMargin(0);
        jtClaims.getColumnModel().setColumnMargin(0);
        jtClaims.getTableHeader().setReorderingAllowed(false);
        jtClaims.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);

        for (int i = 0; i < jtClaims.getColumnCount(); i++) {
            TableColumn column = jtClaims.getColumnModel().getColumn(i);

            if (i == 0) {
                column.setPreferredWidth(100);
            }

            column.setHeaderRenderer(new ClaimsTableHeadRend(jtClaims.getTableHeader().getDefaultRenderer()));
            column.setCellRenderer(new ClaimsTableCellRend());
        }

        jspClaimsTable = PlatformUtil.createScrollPane(jtClaims, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                       ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspClaimsTable.getViewport().setBackground(jtClaims.getBackground());

        jpClaimsButtons = new JPanel();
        jpClaimsButtons.setLayout(new BoxLayout(jpClaimsButtons, BoxLayout.Y_AXIS));
        jpClaimsButtons.add(Box.createVerticalGlue());
        jpClaimsButtons.add(jbAdd);
        jpClaimsButtons.add(Box.createVerticalStrut(3));
        jpClaimsButtons.add(jbEdit);
        jpClaimsButtons.add(Box.createVerticalStrut(3));
        jpClaimsButtons.add(jbRemove);
        jpClaimsButtons.add(Box.createVerticalGlue());

        this.setLayout(new BorderLayout(5, 5));
        this.setPreferredSize(new Dimension(50, 150));
        this.add(jlClaims, BorderLayout.NORTH);
        this.add(jspClaimsTable, BorderLayout.CENTER);
        this.add(jpClaimsButtons, BorderLayout.EAST);
        this.setBorder(new CompoundBorder(new EtchedBorder(), new EmptyBorder(5, 5, 5, 5)));
    }

    protected void maybeEditClaim(MouseEvent evt) {
        if (evt.getClickCount() > 1) {
            Point point = new Point(evt.getX(), evt.getY());
            int row = jtClaims.rowAtPoint(point);

            if (row != -1) {
                try {
                    CursorUtil.setCursorBusy(JClaims.this);
                    jtClaims.setRowSelectionInterval(row, row);
                } finally {
                    CursorUtil.setCursorFree(JClaims.this);
                }
            }
        }
    }

    private void removePressed() {
        int selectedRow = jtClaims.getSelectedRow();

        if (selectedRow != -1) {
            ((ListClaimsTableModel) jtClaims.getModel()).removeRow(selectedRow);
            selectFirstCustomClaimInTable();
            updateButtonControls();
        }

    }

    private void selectFirstCustomClaimInTable() {
        if (getCustomClaimTableModel().getRowCount() > 0) {
            jtClaims.changeSelection(0, 0, false, false);
        }
    }

    private ListClaimsTableModel getCustomClaimTableModel() {
        return (ListClaimsTableModel) jtClaims.getModel();
    }

    private void editPressed() {
        int selectedRow = jtClaims.getSelectedRow();
        if (selectedRow != -1) {
            ListClaimsTableModel model = getCustomClaimTableModel();
            List<CustomClaim> listCustomClaim = model.getData();
            CustomClaim customClaim = listCustomClaim.get(selectedRow);
            DCustomClaim dialog = new DCustomClaim(parent, customClaim.getName(), customClaim.getValue());
            dialog.setLocationRelativeTo(parent);
            dialog.setVisible(true);
            if (dialog.isOk()) {
                customClaim.setName(dialog.getName());
                customClaim.setValue(dialog.getValue());
                model.updateRow(selectedRow, customClaim);
            }
        }
    }

    private void addPressed() {
        DCustomClaim dialog = new DCustomClaim(parent, "", "");
        dialog.setLocationRelativeTo(parent);
        dialog.setVisible(true);
        if (dialog.isOk()) {
            CustomClaim customClaim = new CustomClaim(dialog.getName(), dialog.getValue());
            ListClaimsTableModel rcModel = getCustomClaimTableModel();
            rcModel.addRow(customClaim);
            selectFirstCustomClaimInTable();
            updateButtonControls();
        }
    }

    public List<CustomClaim> getCustomClaims() {
        ListClaimsTableModel model = getCustomClaimTableModel();
        return model.getData();
    }

    private void updateButtonControls() {
        jbAdd.setEnabled(true);

        int selectedRow = jtClaims.getSelectedRow();

        if (selectedRow == -1) {
            jbEdit.setEnabled(false);
            jbRemove.setEnabled(false);
        } else {
            jbEdit.setEnabled(true);
            jbRemove.setEnabled(true);
        }
    }
}
