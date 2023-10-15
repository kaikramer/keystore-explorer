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

package org.kse.gui.crypto.distributionpoints;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ResourceBundle;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.os.OperatingSystem;

public class JDistributionPoints extends JPanel {

    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/distributionpoints/resources");

    private JPanel jpDistributionPointsButtons;
    private JButton jbAdd;
    private JButton jbEdit;
    private JButton jbRemove;
    private JScrollPane jspDistributionPoints;
    private JKseTable jtDistributionPoints;

    private String title;
    private boolean enabled = true;

    public JDistributionPoints(String title) {
        this.title = title;
        initComponents();
    }

    private void initComponents() {
        jbAdd = new JButton(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/add_distribution_nms.png"))));
        jbAdd.setMargin(new Insets(2, 2, 0, 0));
        jbAdd.setToolTipText(res.getString("JDistributionPoints.jbAdd.tooltip"));
        jbAdd.setMnemonic(res.getString("JDistributionPoints.jbAdd.mnemonic").charAt(0));

        jbAdd.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JDistributionPoints.this);
                addPressed();
            } finally {
                CursorUtil.setCursorFree(JDistributionPoints.this);
            }
        });

        jbEdit = new JButton(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/edit_distribution_nms.png"))));
        jbEdit.setMargin(new Insets(2, 2, 0, 0));
        jbEdit.setToolTipText(res.getString("JDistributionPoints.jbEdit.tooltip"));
        jbEdit.setMnemonic(res.getString("JDistributionPoints.jbEdit.mnemonic").charAt(0));

        jbEdit.setEnabled(false);

        jbEdit.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JDistributionPoints.this);
                editPressed();
            } finally {
                CursorUtil.setCursorFree(JDistributionPoints.this);
            }
        });

        jbRemove = new JButton(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/remove_distribution_nms.png"))));
        jbRemove.setMargin(new Insets(2, 2, 0, 0));
        jbRemove.setToolTipText(res.getString("JDistributionPoints.jbRemove.tooltip"));
        jbRemove.setMnemonic(res.getString("JDistributionPoints.jbRemove.mnemonic").charAt(0));

        jbRemove.setEnabled(false);

        jbRemove.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JDistributionPoints.this);
                removePressed();
            } finally {
                CursorUtil.setCursorFree(JDistributionPoints.this);
            }
        });

        jpDistributionPointsButtons = new JPanel();
        jpDistributionPointsButtons.setLayout(new BoxLayout(jpDistributionPointsButtons, BoxLayout.Y_AXIS));
        jpDistributionPointsButtons.add(Box.createVerticalGlue());
        jpDistributionPointsButtons.add(jbAdd);
        jpDistributionPointsButtons.add(Box.createVerticalStrut(3));
        jpDistributionPointsButtons.add(jbEdit);
        jpDistributionPointsButtons.add(Box.createVerticalStrut(3));
        jpDistributionPointsButtons.add(jbRemove);
        jpDistributionPointsButtons.add(Box.createVerticalGlue());

        DistributionPointsTableModel distributionPointsTableModel = new DistributionPointsTableModel();
        jtDistributionPoints = new JKseTable(distributionPointsTableModel);

        TableRowSorter<DistributionPointsTableModel> sorter = new TableRowSorter<>(distributionPointsTableModel);
        sorter.setComparator(0, new DistributionPointsTableModel.DistributionPointComparator());
        jtDistributionPoints.setRowSorter(sorter);

        jtDistributionPoints.setShowGrid(false);
        jtDistributionPoints.setRowMargin(0);
        jtDistributionPoints.getColumnModel().setColumnMargin(0);
        jtDistributionPoints.getTableHeader().setReorderingAllowed(false);
        jtDistributionPoints.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
        jtDistributionPoints.setRowHeight(Math.max(18, jtDistributionPoints.getRowHeight()));

        for (int i = 0; i < jtDistributionPoints.getColumnCount(); i++) {
            TableColumn column = jtDistributionPoints.getColumnModel().getColumn(i);
            column.setHeaderRenderer(
                    new DistributionPointsTableHeadRend(jtDistributionPoints.getTableHeader().getDefaultRenderer()));
            column.setCellRenderer(new DistributionPointsTableCellRend());
        }

        ListSelectionModel selectionModel = jtDistributionPoints.getSelectionModel();
        selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        selectionModel.addListSelectionListener(evt -> {
            if (!evt.getValueIsAdjusting()) {
                updateButtonControls();
            }
        });

        jtDistributionPoints.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent evt) {
                maybeEditGeneralName(evt);
            }
        });

        jtDistributionPoints.addKeyListener(new KeyAdapter() {
            boolean deleteLastPressed = false;

            @Override
            public void keyPressed(KeyEvent evt) {
                // Record delete pressed on non-Macs
                if (!OperatingSystem.isMacOs()) {
                    deleteLastPressed = evt.getKeyCode() == KeyEvent.VK_DELETE;
                }
            }

            @Override
            public void keyReleased(KeyEvent evt) {
                // Delete on non-Mac if delete was pressed and is now released
                if (!OperatingSystem.isMacOs() && deleteLastPressed && evt.getKeyCode() == KeyEvent.VK_DELETE) {
                    try {
                        CursorUtil.setCursorBusy(JDistributionPoints.this);
                        deleteLastPressed = false;
                        removeSelectedDistributionPoint();
                    } finally {
                        CursorUtil.setCursorFree(JDistributionPoints.this);
                    }
                }
            }

            @Override
            public void keyTyped(KeyEvent evt) {
                // Delete on Mac if backspace typed
                if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
                    try {
                        CursorUtil.setCursorBusy(JDistributionPoints.this);
                        removeSelectedDistributionPoint();
                    } finally {
                        CursorUtil.setCursorFree(JDistributionPoints.this);
                    }
                }
            }
        });

        jspDistributionPoints = PlatformUtil.createScrollPane(jtDistributionPoints,
                                                              ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                              ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jspDistributionPoints.getViewport().setBackground(jtDistributionPoints.getBackground());

        this.setLayout(new BorderLayout(5, 5));
        setPreferredSize(new Dimension(250, 150));
        add(jspDistributionPoints, BorderLayout.CENTER);
        add(jpDistributionPointsButtons, BorderLayout.EAST);

        selectFirstGeneralNameInTable();
        updateButtonControls();
    }

    public CRLDistPoint getCRLDistPoint() {
        return new CRLDistPoint(getDistributionPointsTableModel().getData().toArray(new DistributionPoint[0]));
    }

    public void setCRLDistPoint(CRLDistPoint cRLDistPoint) {
        getDistributionPointsTableModel().load(cRLDistPoint);
    }

    /**
     * Sets whether or not the component is enabled.
     *
     * @param enabled True if this component should be enabled, false otherwise
     */
    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;

        updateButtonControls();
    }

    /**
     * Set component's tooltip text.
     *
     * @param toolTipText Tooltip text
     */
    @Override
    public void setToolTipText(String toolTipText) {
        super.setToolTipText(toolTipText);
        jspDistributionPoints.setToolTipText(toolTipText);
        jtDistributionPoints.setToolTipText(toolTipText);
    }

    private void addPressed() {
        Container container = getTopLevelAncestor();

        DDistributionPointsChooser distributionPointsChooser = null;

        if (container instanceof JDialog) {
            distributionPointsChooser = new DDistributionPointsChooser((JDialog) container, title, null);
        } else {
            distributionPointsChooser = new DDistributionPointsChooser((JFrame) container, title, null);
        }

        distributionPointsChooser.setLocationRelativeTo(container);
        distributionPointsChooser.setVisible(true);

        DistributionPoint newDistributionPoint = distributionPointsChooser.getDistributionPoint();

        if (newDistributionPoint == null) {
            return;
        }

        getDistributionPointsTableModel().addRow(newDistributionPoint);

        selectDistributionPointInTable(newDistributionPoint);
        updateButtonControls();
    }

    private void removePressed() {
        removeSelectedDistributionPoint();
    }

    private void removeSelectedDistributionPoint() {
        int selectedRow = jtDistributionPoints.getSelectedRow();

        if (selectedRow != -1) {
            ((DistributionPointsTableModel) jtDistributionPoints.getModel()).removeRow(selectedRow);

            selectFirstGeneralNameInTable();
            updateButtonControls();
        }
    }

    private void editPressed() {
        editSelectedGeneralName();
    }

    private void maybeEditGeneralName(MouseEvent evt) {
        if (evt.getClickCount() > 1) {
            Point point = new Point(evt.getX(), evt.getY());
            int row = jtDistributionPoints.rowAtPoint(point);

            if (row != -1) {
                try {
                    CursorUtil.setCursorBusy(JDistributionPoints.this);
                    jtDistributionPoints.setRowSelectionInterval(row, row);
                    editSelectedGeneralName();
                } finally {
                    CursorUtil.setCursorFree(JDistributionPoints.this);
                }
            }
        }
    }

    private void updateButtonControls() {
        if (!enabled) {
            jbAdd.setEnabled(false);
            jbEdit.setEnabled(false);
            jbRemove.setEnabled(false);
        } else {
            jbAdd.setEnabled(true);

            int selectedRow = jtDistributionPoints.getSelectedRow();

            if (selectedRow == -1) {
                jbEdit.setEnabled(false);
                jbRemove.setEnabled(false);
            } else {
                jbEdit.setEnabled(true);
                jbRemove.setEnabled(true);
            }
        }
    }

    private void editSelectedGeneralName() {
        int selectedRow = jtDistributionPoints.getSelectedRow();

        if (selectedRow != -1) {

            DistributionPoint distributionPoint = (DistributionPoint) jtDistributionPoints.getValueAt(selectedRow, 0);

            Container container = getTopLevelAncestor();

            DDistributionPointsChooser distributionPointsChooser = null;

            if (container instanceof JDialog) {
                distributionPointsChooser = new DDistributionPointsChooser((JDialog) container, title,
                                                                           distributionPoint);
            } else {
                distributionPointsChooser = new DDistributionPointsChooser((JFrame) container, title,
                                                                           distributionPoint);
            }

            distributionPointsChooser.setLocationRelativeTo(container);
            distributionPointsChooser.setVisible(true);

            DistributionPoint newDistributionPoint = distributionPointsChooser.getDistributionPoint();

            if (newDistributionPoint == null) {
                return;
            }

            getDistributionPointsTableModel().removeRow(selectedRow);
            getDistributionPointsTableModel().addRow(newDistributionPoint);

            selectDistributionPointInTable(newDistributionPoint);
            updateButtonControls();
        }
    }

    private void selectDistributionPointInTable(DistributionPoint newDistributionPoint) {
        for (int i = 0; i < jtDistributionPoints.getRowCount(); i++) {
            if (newDistributionPoint.equals(jtDistributionPoints.getValueAt(i, 0))) {
                jtDistributionPoints.changeSelection(i, 0, false, false);
                return;
            }
        }
    }

    private void selectFirstGeneralNameInTable() {
        if (getDistributionPointsTableModel().getRowCount() > 0) {
            jtDistributionPoints.changeSelection(0, 0, false, false);
        }
    }

    private DistributionPointsTableModel getDistributionPointsTableModel() {
        return (DistributionPointsTableModel) jtDistributionPoints.getModel();
    }

}
