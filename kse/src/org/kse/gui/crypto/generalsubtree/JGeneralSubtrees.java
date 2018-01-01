/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
package org.kse.gui.crypto.generalsubtree;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
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
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.kse.crypto.x509.GeneralSubtrees;
import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.os.OperatingSystem;

/**
 * Component to edit a set of general subtrees.
 *
 */
public class JGeneralSubtrees extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/generalsubtree/resources");

	private JPanel jpGeneralSubtreeButtons;
	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbRemove;
	private JScrollPane jspGeneralSubtrees;
	private JKseTable jtGeneralSubtrees;

	private String title;
	private GeneralSubtrees generalSubtrees;
	private boolean enabled = true;

	/**
	 * Construct a JGeneralSubtrees.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JGeneralSubtrees(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jbAdd = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JGeneralSubtrees.jbAdd.image")))));
		jbAdd.setMargin(new Insets(2, 2, 0, 0));
		jbAdd.setToolTipText(res.getString("JGeneralSubtrees.jbAdd.tooltip"));
		jbAdd.setMnemonic(res.getString("JGeneralSubtrees.jbAdd.mnemonic").charAt(0));

		jbAdd.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JGeneralSubtrees.this);
					addPressed();
				} finally {
					CursorUtil.setCursorFree(JGeneralSubtrees.this);
				}
			}
		});

		jbEdit = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JGeneralSubtrees.jbEdit.image")))));
		jbEdit.setMargin(new Insets(2, 2, 0, 0));
		jbEdit.setToolTipText(res.getString("JGeneralSubtrees.jbEdit.tooltip"));
		jbEdit.setMnemonic(res.getString("JGeneralSubtrees.jbEdit.mnemonic").charAt(0));

		jbEdit.setEnabled(false);

		jbEdit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JGeneralSubtrees.this);
					editPressed();
				} finally {
					CursorUtil.setCursorFree(JGeneralSubtrees.this);
				}
			}
		});

		jbRemove = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JGeneralSubtrees.jbRemove.image")))));
		jbRemove.setMargin(new Insets(2, 2, 0, 0));
		jbRemove.setToolTipText(res.getString("JGeneralSubtrees.jbRemove.tooltip"));
		jbRemove.setMnemonic(res.getString("JGeneralSubtrees.jbRemove.mnemonic").charAt(0));

		jbRemove.setEnabled(false);

		jbRemove.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JGeneralSubtrees.this);
					removePressed();
				} finally {
					CursorUtil.setCursorFree(JGeneralSubtrees.this);
				}
			}
		});

		jpGeneralSubtreeButtons = new JPanel();
		jpGeneralSubtreeButtons.setLayout(new BoxLayout(jpGeneralSubtreeButtons, BoxLayout.Y_AXIS));
		jpGeneralSubtreeButtons.add(Box.createVerticalGlue());
		jpGeneralSubtreeButtons.add(jbAdd);
		jpGeneralSubtreeButtons.add(Box.createVerticalStrut(3));
		jpGeneralSubtreeButtons.add(jbEdit);
		jpGeneralSubtreeButtons.add(Box.createVerticalStrut(3));
		jpGeneralSubtreeButtons.add(jbRemove);
		jpGeneralSubtreeButtons.add(Box.createVerticalGlue());

		GeneralSubtreesTableModel generalSubtreesTableModel = new GeneralSubtreesTableModel();
		jtGeneralSubtrees = new JKseTable(generalSubtreesTableModel);

		TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(generalSubtreesTableModel);
		sorter.setComparator(0, new GeneralSubtreesTableModel.GeneralSubtreeBaseComparator());
		sorter.setComparator(1, new GeneralSubtreesTableModel.GeneralSubtreeMinimumComparator());
		sorter.setComparator(2, new GeneralSubtreesTableModel.GeneralSubtreeMaximumComparator());
		jtGeneralSubtrees.setRowSorter(sorter);

		jtGeneralSubtrees.setShowGrid(false);
		jtGeneralSubtrees.setRowMargin(0);
		jtGeneralSubtrees.getColumnModel().setColumnMargin(0);
		jtGeneralSubtrees.getTableHeader().setReorderingAllowed(false);
		jtGeneralSubtrees.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
		jtGeneralSubtrees.setRowHeight(Math.max(18, jtGeneralSubtrees.getRowHeight()));

		for (int i = 0; i < jtGeneralSubtrees.getColumnCount(); i++) {
			TableColumn column = jtGeneralSubtrees.getColumnModel().getColumn(i);
			column.setHeaderRenderer(new GeneralSubtreesTableHeadRend(jtGeneralSubtrees.getTableHeader()
					.getDefaultRenderer()));
			column.setCellRenderer(new GeneralSubtreesTableCellRend());
		}

		ListSelectionModel selectionModel = jtGeneralSubtrees.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					updateButtonControls();
				}
			}
		});

		jtGeneralSubtrees.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeEditGeneralSubtree(evt);
			}
		});

		jtGeneralSubtrees.addKeyListener(new KeyAdapter() {
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
						CursorUtil.setCursorBusy(JGeneralSubtrees.this);
						deleteLastPressed = false;
						removeSelectedGeneralSubtree();
					} finally {
						CursorUtil.setCursorFree(JGeneralSubtrees.this);
					}
				}
			}

			@Override
			public void keyTyped(KeyEvent evt) {
				// Delete on Mac if back space typed
				if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
					try {
						CursorUtil.setCursorBusy(JGeneralSubtrees.this);
						removeSelectedGeneralSubtree();
					} finally {
						CursorUtil.setCursorFree(JGeneralSubtrees.this);
					}
				}
			}
		});

		jspGeneralSubtrees = PlatformUtil.createScrollPane(jtGeneralSubtrees,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspGeneralSubtrees.getViewport().setBackground(jtGeneralSubtrees.getBackground());

		this.setLayout(new BorderLayout(5, 5));
		setPreferredSize(new Dimension(400, 150));
		add(jspGeneralSubtrees, BorderLayout.CENTER);
		add(jpGeneralSubtreeButtons, BorderLayout.EAST);

		populate();
	}

	/**
	 * Get general subtrees.
	 *
	 * @return General subtrees
	 */
	public GeneralSubtrees getGeneralSubtrees() {
		return generalSubtrees;
	}

	/**
	 * Set general subtrees.
	 *
	 * @param generalSubtrees
	 *            General subtrees
	 */
	public void setGeneralSubtrees(GeneralSubtrees generalSubtrees) {
		this.generalSubtrees = generalSubtrees;
		populate();
	}

	/**
	 * Sets whether or not the component is enabled.
	 *
	 * @param enabled
	 *            True if this component should be enabled, false otherwise
	 */
	@Override
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
		updateButtonControls();
	}

	/**
	 * Set component's tooltip text.
	 *
	 * @param toolTipText
	 *            Tooltip text
	 */
	@Override
	public void setToolTipText(String toolTipText) {
		super.setToolTipText(toolTipText);
		jspGeneralSubtrees.setToolTipText(toolTipText);
		jtGeneralSubtrees.setToolTipText(toolTipText);
	}

	private void populate() {
		if (generalSubtrees == null) {
			generalSubtrees = new GeneralSubtrees(new ArrayList<GeneralSubtree>());
		}

		reloadGeneralSubtreesTable();
		selectFirstGeneralSubtreeInTable();
		updateButtonControls();
	}

	private void addPressed() {
		Container container = getTopLevelAncestor();

		DGeneralSubtreeChooser dGeneralSubtreeChooser = null;

		if (container instanceof JDialog) {
			dGeneralSubtreeChooser = new DGeneralSubtreeChooser((JDialog) container, title, null);
			dGeneralSubtreeChooser.setLocationRelativeTo(container);
			dGeneralSubtreeChooser.setVisible(true);
		} else if (container instanceof JFrame) {
			dGeneralSubtreeChooser = new DGeneralSubtreeChooser((JFrame) container, title, null);
			dGeneralSubtreeChooser.setLocationRelativeTo(container);
			dGeneralSubtreeChooser.setVisible(true);
		}

		GeneralSubtree newGeneralSubtree = dGeneralSubtreeChooser.getGeneralSubtree();

		if (newGeneralSubtree == null) {
			return;
		}

		generalSubtrees.getGeneralSubtrees().add(newGeneralSubtree);

		populate();
		selectGeneralSubtreeInTable(newGeneralSubtree);
	}

	private void removePressed() {
		removeSelectedGeneralSubtree();
	}

	private void removeSelectedGeneralSubtree() {
		int selectedRow = jtGeneralSubtrees.getSelectedRow();

		if (selectedRow != -1) {
			GeneralSubtree generalSubtree = (GeneralSubtree) jtGeneralSubtrees.getValueAt(selectedRow, 0);

			generalSubtrees.getGeneralSubtrees().remove(generalSubtree);

			reloadGeneralSubtreesTable();
			selectFirstGeneralSubtreeInTable();
			updateButtonControls();
		}
	}

	private void editPressed() {
		editSelectedGeneralSubtree();
	}

	private void maybeEditGeneralSubtree(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			Point point = new Point(evt.getX(), evt.getY());
			int row = jtGeneralSubtrees.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(JGeneralSubtrees.this);
					jtGeneralSubtrees.setRowSelectionInterval(row, row);
					editSelectedGeneralSubtree();
				} finally {
					CursorUtil.setCursorFree(JGeneralSubtrees.this);
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

			int selectedRow = jtGeneralSubtrees.getSelectedRow();

			if (selectedRow == -1) {
				jbEdit.setEnabled(false);
				jbRemove.setEnabled(false);
			} else {
				jbEdit.setEnabled(true);
				jbRemove.setEnabled(true);
			}
		}
	}

	private void editSelectedGeneralSubtree() {
		int selectedRow = jtGeneralSubtrees.getSelectedRow();

		if (selectedRow != -1) {
			GeneralSubtree generalSubtree = (GeneralSubtree) jtGeneralSubtrees.getValueAt(selectedRow, 0);

			Container container = getTopLevelAncestor();

			DGeneralSubtreeChooser dGeneralSubtreeChooser = null;

			if (container instanceof JDialog) {
				dGeneralSubtreeChooser = new DGeneralSubtreeChooser((JDialog) container, title, generalSubtree);
				dGeneralSubtreeChooser.setLocationRelativeTo(container);
				dGeneralSubtreeChooser.setVisible(true);
			} else if (container instanceof JFrame) {
				dGeneralSubtreeChooser = new DGeneralSubtreeChooser((JFrame) container, title, generalSubtree);
				dGeneralSubtreeChooser.setLocationRelativeTo(container);
				dGeneralSubtreeChooser.setVisible(true);
			}

			GeneralSubtree newGeneralSubtree = dGeneralSubtreeChooser.getGeneralSubtree();

			if (newGeneralSubtree == null) {
				return;
			}

			generalSubtrees.getGeneralSubtrees().remove(generalSubtree);
			generalSubtrees.getGeneralSubtrees().add(newGeneralSubtree);

			populate();
			selectGeneralSubtreeInTable(newGeneralSubtree);
		}
	}

	private void selectGeneralSubtreeInTable(GeneralSubtree generalSubtree) {
		for (int i = 0; i < jtGeneralSubtrees.getRowCount(); i++) {
			if (generalSubtree.equals(jtGeneralSubtrees.getValueAt(i, 0))) {
				jtGeneralSubtrees.changeSelection(i, 0, false, false);
				return;
			}
		}
	}

	private void reloadGeneralSubtreesTable() {
		getGeneralSubtreesTableModel().load(generalSubtrees);
	}

	private void selectFirstGeneralSubtreeInTable() {
		if (getGeneralSubtreesTableModel().getRowCount() > 0) {
			jtGeneralSubtrees.changeSelection(0, 0, false, false);
		}
	}

	private GeneralSubtreesTableModel getGeneralSubtreesTableModel() {
		return (GeneralSubtreesTableModel) jtGeneralSubtrees.getModel();
	}
}
