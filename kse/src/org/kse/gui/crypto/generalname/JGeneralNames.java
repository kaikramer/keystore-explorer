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
package org.kse.gui.crypto.generalname;

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

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.os.OperatingSystem;

/**
 * Component to edit a set of general names.
 *
 */
public class JGeneralNames extends JPanel {
	private static final long serialVersionUID = 459512931464920941L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/generalname/resources");

	private JPanel jpGeneralNameButtons;
	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbRemove;
	private JScrollPane jspGeneralNames;
	private JKseTable jtGeneralNames;

	private String title;
	private boolean enabled = true;

	/**
	 * Construct a JGeneralNames.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JGeneralNames(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jbAdd = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JGeneralNames.jbAdd.image")))));
		jbAdd.setMargin(new Insets(2, 2, 0, 0));
		jbAdd.setToolTipText(res.getString("JGeneralNames.jbAdd.tooltip"));
		jbAdd.setMnemonic(res.getString("JGeneralNames.jbAdd.mnemonic").charAt(0));

		jbAdd.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JGeneralNames.this);
					addPressed();
				} finally {
					CursorUtil.setCursorFree(JGeneralNames.this);
				}
			}
		});

		jbEdit = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JGeneralNames.jbEdit.image")))));
		jbEdit.setMargin(new Insets(2, 2, 0, 0));
		jbEdit.setToolTipText(res.getString("JGeneralNames.jbEdit.tooltip"));
		jbEdit.setMnemonic(res.getString("JGeneralNames.jbEdit.mnemonic").charAt(0));

		jbEdit.setEnabled(false);

		jbEdit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JGeneralNames.this);
					editPressed();
				} finally {
					CursorUtil.setCursorFree(JGeneralNames.this);
				}
			}
		});

		jbRemove = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JGeneralNames.jbRemove.image")))));
		jbRemove.setMargin(new Insets(2, 2, 0, 0));
		jbRemove.setToolTipText(res.getString("JGeneralNames.jbRemove.tooltip"));
		jbRemove.setMnemonic(res.getString("JGeneralNames.jbRemove.mnemonic").charAt(0));

		jbRemove.setEnabled(false);

		jbRemove.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JGeneralNames.this);
					removePressed();
				} finally {
					CursorUtil.setCursorFree(JGeneralNames.this);
				}
			}
		});

		jpGeneralNameButtons = new JPanel();
		jpGeneralNameButtons.setLayout(new BoxLayout(jpGeneralNameButtons, BoxLayout.Y_AXIS));
		jpGeneralNameButtons.add(Box.createVerticalGlue());
		jpGeneralNameButtons.add(jbAdd);
		jpGeneralNameButtons.add(Box.createVerticalStrut(3));
		jpGeneralNameButtons.add(jbEdit);
		jpGeneralNameButtons.add(Box.createVerticalStrut(3));
		jpGeneralNameButtons.add(jbRemove);
		jpGeneralNameButtons.add(Box.createVerticalGlue());

		GeneralNamesTableModel generalNamesTableModel = new GeneralNamesTableModel();
		jtGeneralNames = new JKseTable(generalNamesTableModel);

		TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(generalNamesTableModel);
		sorter.setComparator(0, new GeneralNamesTableModel.GeneralNameComparator());
		jtGeneralNames.setRowSorter(sorter);

		jtGeneralNames.setShowGrid(false);
		jtGeneralNames.setRowMargin(0);
		jtGeneralNames.getColumnModel().setColumnMargin(0);
		jtGeneralNames.getTableHeader().setReorderingAllowed(false);
		jtGeneralNames.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
		jtGeneralNames.setRowHeight(Math.max(18, jtGeneralNames.getRowHeight()));

		for (int i = 0; i < jtGeneralNames.getColumnCount(); i++) {
			TableColumn column = jtGeneralNames.getColumnModel().getColumn(i);
			column.setHeaderRenderer(new GeneralNamesTableHeadRend(jtGeneralNames.getTableHeader().getDefaultRenderer()));
			column.setCellRenderer(new GeneralNamesTableCellRend());
		}

		ListSelectionModel selectionModel = jtGeneralNames.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					updateButtonControls();
				}
			}
		});

		jtGeneralNames.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeEditGeneralName(evt);
			}
		});

		jtGeneralNames.addKeyListener(new KeyAdapter() {
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
						CursorUtil.setCursorBusy(JGeneralNames.this);
						deleteLastPressed = false;
						removeSelectedGeneralName();
					} finally {
						CursorUtil.setCursorFree(JGeneralNames.this);
					}
				}
			}

			@Override
			public void keyTyped(KeyEvent evt) {
				// Delete on Mac if back space typed
				if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
					try {
						CursorUtil.setCursorBusy(JGeneralNames.this);
						removeSelectedGeneralName();
					} finally {
						CursorUtil.setCursorFree(JGeneralNames.this);
					}
				}
			}
		});

		jspGeneralNames = PlatformUtil.createScrollPane(jtGeneralNames,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspGeneralNames.getViewport().setBackground(jtGeneralNames.getBackground());

		this.setLayout(new BorderLayout(5, 5));
		setPreferredSize(new Dimension(250, 150));
		add(jspGeneralNames, BorderLayout.CENTER);
		add(jpGeneralNameButtons, BorderLayout.EAST);

		selectFirstGeneralNameInTable();
		updateButtonControls();
	}

	/**
	 * Get general names.
	 *
	 * @return General names
	 */
	public GeneralNames getGeneralNames() {
		return new GeneralNames(getGeneralNamesTableModel().getData().toArray(new GeneralName[0]));
	}

	/**
	 * Set general names.
	 *
	 * @param generalNames
	 *            General names
	 */
	public void setGeneralNames(GeneralNames generalNames) {
		getGeneralNamesTableModel().load(generalNames);
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
		jspGeneralNames.setToolTipText(toolTipText);
		jtGeneralNames.setToolTipText(toolTipText);
	}

	private void addPressed() {
		Container container = getTopLevelAncestor();

		DGeneralNameChooser dGeneralNameChooser = null;

		if (container instanceof JDialog) {
			dGeneralNameChooser = new DGeneralNameChooser((JDialog) container, title, null);
			dGeneralNameChooser.setLocationRelativeTo(container);
			dGeneralNameChooser.setVisible(true);
		} else if (container instanceof JFrame) {
			dGeneralNameChooser = new DGeneralNameChooser((JFrame) container, title, null);
			dGeneralNameChooser.setLocationRelativeTo(container);
			dGeneralNameChooser.setVisible(true);
		}

		GeneralName newGeneralName = dGeneralNameChooser.getGeneralName();

		if (newGeneralName == null) {
			return;
		}

		getGeneralNamesTableModel().addRow(newGeneralName);

		selectGeneralNameInTable(newGeneralName);
		updateButtonControls();
	}

	private void removePressed() {
		removeSelectedGeneralName();
	}

	private void removeSelectedGeneralName() {
		int selectedRow = jtGeneralNames.getSelectedRow();

		if (selectedRow != -1) {
			((GeneralNamesTableModel) jtGeneralNames.getModel()).removeRow(selectedRow);

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
			int row = jtGeneralNames.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(JGeneralNames.this);
					jtGeneralNames.setRowSelectionInterval(row, row);
					editSelectedGeneralName();
				} finally {
					CursorUtil.setCursorFree(JGeneralNames.this);
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

			int selectedRow = jtGeneralNames.getSelectedRow();

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
		int selectedRow = jtGeneralNames.getSelectedRow();

		if (selectedRow != -1) {
			GeneralName generalName = (GeneralName) jtGeneralNames.getValueAt(selectedRow, 0);

			Container container = getTopLevelAncestor();

			DGeneralNameChooser dGeneralNameChooser = null;

			if (container instanceof JDialog) {
				dGeneralNameChooser = new DGeneralNameChooser((JDialog) container, title, generalName);
				dGeneralNameChooser.setLocationRelativeTo(container);
				dGeneralNameChooser.setVisible(true);
			} else if (container instanceof JFrame) {
				dGeneralNameChooser = new DGeneralNameChooser((JFrame) container, title, generalName);
				dGeneralNameChooser.setLocationRelativeTo(container);
				dGeneralNameChooser.setVisible(true);
			}

			GeneralName newGeneralName = dGeneralNameChooser.getGeneralName();

			if (newGeneralName == null) {
				return;
			}

			getGeneralNamesTableModel().removeRow(selectedRow);
			getGeneralNamesTableModel().addRow(newGeneralName);

			selectGeneralNameInTable(newGeneralName);
			updateButtonControls();
		}
	}

	private void selectGeneralNameInTable(GeneralName generalName) {
		for (int i = 0; i < jtGeneralNames.getRowCount(); i++) {
			if (generalName.equals(jtGeneralNames.getValueAt(i, 0))) {
				jtGeneralNames.changeSelection(i, 0, false, false);
				return;
			}
		}
	}

	private void selectFirstGeneralNameInTable() {
		if (getGeneralNamesTableModel().getRowCount() > 0) {
			jtGeneralNames.changeSelection(0, 0, false, false);
		}
	}

	private GeneralNamesTableModel getGeneralNamesTableModel() {
		return (GeneralNamesTableModel) jtGeneralNames.getModel();
	}
}
