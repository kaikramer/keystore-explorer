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
package org.kse.gui.crypto;

import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;

import org.kse.gui.CursorUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.table.LoadableTableModel;
import org.kse.utilities.os.OperatingSystem;

import net.miginfocom.swing.MigLayout;

/**
 * Abstract component with infrastructure to edit a set of items.
 *
 * @param <C> the type of collection.
 * @param <E> the type of elements to be managed.
 */
public abstract class JAddEditRemovePanel<C extends Collection<E>, E> extends JPanel {
    private static final long serialVersionUID = 1L;

    private JButton jbAdd;
    private JButton jbEdit;
    private JButton jbRemove;
    private JScrollPane jspTable;
    private JTable jtTable;

    private C items;
    private boolean enabled = true;

    protected JAddEditRemovePanel() {
        initComponents();
    }

    protected abstract String getAddResource();
    protected abstract String getEditResource();
    protected abstract String getRemoveResource();
    protected abstract String getBundleString(String suffix);
    protected abstract C newCollection();
    protected abstract JTable newTable();
    protected abstract E getItem(E item);

    private void initComponents() {
        jbAdd = new JButton(
                new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(getAddResource()))));
        jbAdd.setMargin(new Insets(2, 2, 2, 2));
        jbAdd.setToolTipText(getBundleString("jbAdd.tooltip"));
        jbAdd.setMnemonic(getBundleString("jbAdd.mnemonic").charAt(0));

        jbAdd.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JAddEditRemovePanel.this);
                addPressed();
            } finally {
                CursorUtil.setCursorFree(JAddEditRemovePanel.this);
            }
        });

        jbEdit = new JButton(
                new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(getEditResource()))));
        jbEdit.setMargin(new Insets(2, 2, 2, 2));
        jbEdit.setToolTipText(getBundleString("jbEdit.tooltip"));
        jbEdit.setMnemonic(getBundleString("jbEdit.mnemonic").charAt(0));

        jbEdit.setEnabled(false);

        jbEdit.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JAddEditRemovePanel.this);
                editPressed();
            } finally {
                CursorUtil.setCursorFree(JAddEditRemovePanel.this);
            }
        });

        jbRemove = new JButton(
                new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(getRemoveResource()))));
        jbRemove.setMargin(new Insets(2, 2, 2, 2));
        jbRemove.setToolTipText(getBundleString("jbRemove.tooltip"));
        jbRemove.setMnemonic(getBundleString("jbRemove.mnemonic").charAt(0));

        jbRemove.setEnabled(false);

        jbRemove.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JAddEditRemovePanel.this);
                removePressed();
            } finally {
                CursorUtil.setCursorFree(JAddEditRemovePanel.this);
            }
        });

        jtTable = newTable();

        ListSelectionModel selectionModel = jtTable.getSelectionModel();
        selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        selectionModel.addListSelectionListener(evt -> {
            if (!evt.getValueIsAdjusting()) {
                updateButtonControls();
            }
        });

        jtTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent evt) {
                maybeEditAccessDescription(evt);
            }
        });

        jtTable.addKeyListener(new KeyAdapter() {
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
                        CursorUtil.setCursorBusy(JAddEditRemovePanel.this);
                        deleteLastPressed = false;
                        removeSelectedItem();
                    } finally {
                        CursorUtil.setCursorFree(JAddEditRemovePanel.this);
                    }
                }
            }

            @Override
            public void keyTyped(KeyEvent evt) {
                // Delete on Mac if backspace typed
                if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
                    try {
                        CursorUtil.setCursorBusy(JAddEditRemovePanel.this);
                        removeSelectedItem();
                    } finally {
                        CursorUtil.setCursorFree(JAddEditRemovePanel.this);
                    }
                }
            }
        });

        jspTable = PlatformUtil.createScrollPane(jtTable,
                                                              ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                              ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jspTable.getViewport().setBackground(jtTable.getBackground());

        setPreferredSize(new Dimension(400, 150));

        // layout
        setLayout(new MigLayout("insets 0, fill", "[]", "[]"));
        add(jspTable, "grow, push");
        add(jbAdd, "split 3, flowy");
        add(jbEdit);
        add(jbRemove, "wrap rel");

        populate();
    }

    /**
     * Get the items.
     *
     * @return The collection of items.
     */
    public C getItems() {
        return items;
    }

    /**
     * Set items.
     *
     * @param items Items to set for the Add/Edit/Remove panel
     */
    public void setItems(C items) {
        this.items = items;
        populate();
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
        jspTable.setToolTipText(toolTipText);
        jtTable.setToolTipText(toolTipText);
    }

    private void populate() {
        if (items == null) {
            items = newCollection();
        }

        reloadTable();
        selectFirstItemInTable();
        updateButtonControls();
    }

    private void addPressed() {
        E newItem = getItem(null);

        if (newItem == null) {
            return;
        }

        items.add(newItem);

        populate();
        selectItemInTable(newItem);
    }

    private void removePressed() {
        removeSelectedItem();
    }

    protected void removeSelectedItem() {
        int selectedRow = jtTable.getSelectedRow();

        if (selectedRow != -1) {
            Object item = jtTable.getValueAt(selectedRow, 0);

            items.remove(item);

            reloadTable();
            selectFirstItemInTable();
            updateButtonControls();
        }
    }

    private void editPressed() {
        editSelectedAccessDescription();
    }

    private void maybeEditAccessDescription(MouseEvent evt) {
        if (evt.getClickCount() > 1) {
            Point point = new Point(evt.getX(), evt.getY());
            int row = jtTable.rowAtPoint(point);

            if (row != -1) {
                try {
                    CursorUtil.setCursorBusy(JAddEditRemovePanel.this);
                    jtTable.setRowSelectionInterval(row, row);
                    editSelectedAccessDescription();
                } finally {
                    CursorUtil.setCursorFree(JAddEditRemovePanel.this);
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

            int selectedRow = jtTable.getSelectedRow();

            if (selectedRow == -1) {
                jbEdit.setEnabled(false);
                jbRemove.setEnabled(false);
            } else {
                jbEdit.setEnabled(true);
                jbRemove.setEnabled(true);
            }
        }
    }

    private void editSelectedAccessDescription() {
        int selectedRow = jtTable.getSelectedRow();

        if (selectedRow != -1) {
            @SuppressWarnings("unchecked")
            E item = (E) jtTable.getValueAt(selectedRow, 0);

            E newItem = getItem(item);

            if (newItem == null) {
                return;
            }

            items.remove(item);
            items.add(newItem);

            populate();
            selectItemInTable(newItem);
        }
    }

    private void selectItemInTable(E item) {
        for (int i = 0; i < jtTable.getRowCount(); i++) {
            if (item.equals(jtTable.getValueAt(i, 0))) {
                jtTable.changeSelection(i, 0, false, false);
                return;
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void reloadTable() {
        List<E> tableList;
        if (items instanceof List) {
            tableList = (List<E>) items;
        } else {
            tableList = new ArrayList<>(items);
        }
        getItemsTableModel().load(tableList);
    }

    private void selectFirstItemInTable() {
        if (jtTable.getModel().getRowCount() > 0) {
            jtTable.changeSelection(0, 0, false, false);
        }
    }

    @SuppressWarnings("unchecked")
    private LoadableTableModel<E> getItemsTableModel() {
        return (LoadableTableModel<E>) jtTable.getModel();
    }
}
