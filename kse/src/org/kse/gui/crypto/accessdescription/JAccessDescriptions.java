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
package org.kse.gui.crypto.accessdescription;

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
import java.util.List;
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

import org.bouncycastle.asn1.x509.AccessDescription;
import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.os.OperatingSystem;

/**
 * Component to edit a set of access descriptions.
 *
 */
public class JAccessDescriptions extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/accessdescription/resources");

	private JPanel jpAccessDescriptionButtons;
	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbRemove;
	private JScrollPane jspAccessDescriptions;
	private JKseTable jtAccessDescriptions;

	private String title;
	private List<AccessDescription> accessDescriptions;
	private boolean enabled = true;

	/**
	 * Construct a JAccessDescriptions.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JAccessDescriptions(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jbAdd = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JAccessDescriptions.jbAdd.image")))));
		jbAdd.setMargin(new Insets(2, 2, 0, 0));
		jbAdd.setToolTipText(res.getString("JAccessDescriptions.jbAdd.tooltip"));
		jbAdd.setMnemonic(res.getString("JAccessDescriptions.jbAdd.mnemonic").charAt(0));

		jbAdd.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JAccessDescriptions.this);
					addPressed();
				} finally {
					CursorUtil.setCursorFree(JAccessDescriptions.this);
				}
			}
		});

		jbEdit = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JAccessDescriptions.jbEdit.image")))));
		jbEdit.setMargin(new Insets(2, 2, 0, 0));
		jbEdit.setToolTipText(res.getString("JAccessDescriptions.jbEdit.tooltip"));
		jbEdit.setMnemonic(res.getString("JAccessDescriptions.jbEdit.mnemonic").charAt(0));

		jbEdit.setEnabled(false);

		jbEdit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JAccessDescriptions.this);
					editPressed();
				} finally {
					CursorUtil.setCursorFree(JAccessDescriptions.this);
				}
			}
		});

		jbRemove = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JAccessDescriptions.jbRemove.image")))));
		jbRemove.setMargin(new Insets(2, 2, 0, 0));
		jbRemove.setToolTipText(res.getString("JAccessDescriptions.jbRemove.tooltip"));
		jbRemove.setMnemonic(res.getString("JAccessDescriptions.jbRemove.mnemonic").charAt(0));

		jbRemove.setEnabled(false);

		jbRemove.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JAccessDescriptions.this);
					removePressed();
				} finally {
					CursorUtil.setCursorFree(JAccessDescriptions.this);
				}
			}
		});

		jpAccessDescriptionButtons = new JPanel();
		jpAccessDescriptionButtons.setLayout(new BoxLayout(jpAccessDescriptionButtons, BoxLayout.Y_AXIS));
		jpAccessDescriptionButtons.add(Box.createVerticalGlue());
		jpAccessDescriptionButtons.add(jbAdd);
		jpAccessDescriptionButtons.add(Box.createVerticalStrut(3));
		jpAccessDescriptionButtons.add(jbEdit);
		jpAccessDescriptionButtons.add(Box.createVerticalStrut(3));
		jpAccessDescriptionButtons.add(jbRemove);
		jpAccessDescriptionButtons.add(Box.createVerticalGlue());

		AccessDescriptionsTableModel accessDescriptionsTableModel = new AccessDescriptionsTableModel();
		jtAccessDescriptions = new JKseTable(accessDescriptionsTableModel);

		TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(accessDescriptionsTableModel);
		sorter.setComparator(0, new AccessDescriptionsTableModel.AccessDescriptionMethodComparator());
		sorter.setComparator(1, new AccessDescriptionsTableModel.AccessDescriptionLocationComparator());
		jtAccessDescriptions.setRowSorter(sorter);

		jtAccessDescriptions.setShowGrid(false);
		jtAccessDescriptions.setRowMargin(0);
		jtAccessDescriptions.getColumnModel().setColumnMargin(0);
		jtAccessDescriptions.getTableHeader().setReorderingAllowed(false);
		jtAccessDescriptions.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
		jtAccessDescriptions.setRowHeight(Math.max(18, jtAccessDescriptions.getRowHeight()));

		for (int i = 0; i < jtAccessDescriptions.getColumnCount(); i++) {
			TableColumn column = jtAccessDescriptions.getColumnModel().getColumn(i);
			column.setHeaderRenderer(new AccessDescriptionsTableHeadRend(jtAccessDescriptions.getTableHeader()
					.getDefaultRenderer()));
			column.setCellRenderer(new AccessDescriptionsTableCellRend());
		}

		ListSelectionModel selectionModel = jtAccessDescriptions.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					updateButtonControls();
				}
			}
		});

		jtAccessDescriptions.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeEditAccessDescription(evt);
			}
		});

		jtAccessDescriptions.addKeyListener(new KeyAdapter() {
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
						CursorUtil.setCursorBusy(JAccessDescriptions.this);
						deleteLastPressed = false;
						removeSelectedAccessDescription();
					} finally {
						CursorUtil.setCursorFree(JAccessDescriptions.this);
					}
				}
			}

			@Override
			public void keyTyped(KeyEvent evt) {
				// Delete on Mac if back space typed
				if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
					try {
						CursorUtil.setCursorBusy(JAccessDescriptions.this);
						removeSelectedAccessDescription();
					} finally {
						CursorUtil.setCursorFree(JAccessDescriptions.this);
					}
				}
			}
		});

		jspAccessDescriptions = PlatformUtil.createScrollPane(jtAccessDescriptions,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspAccessDescriptions.getViewport().setBackground(jtAccessDescriptions.getBackground());

		this.setLayout(new BorderLayout(5, 5));
		setPreferredSize(new Dimension(400, 150));
		add(jspAccessDescriptions, BorderLayout.CENTER);
		add(jpAccessDescriptionButtons, BorderLayout.EAST);

		populate();
	}

	/**
	 * Get access descriptions.
	 *
	 * @return Access descriptions
	 */
	public List<AccessDescription> getAccessDescriptions() {
		return accessDescriptions;
	}

	/**
	 * Set access descriptions.
	 *
	 * @param accessDescriptions
	 *            Access descriptions
	 */
	public void setAccessDescriptions(List<AccessDescription> accessDescriptions) {
		this.accessDescriptions = accessDescriptions;
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
		jspAccessDescriptions.setToolTipText(toolTipText);
		jtAccessDescriptions.setToolTipText(toolTipText);
	}

	private void populate() {
		if (accessDescriptions == null) {
			accessDescriptions = new ArrayList<AccessDescription>();
		}

		reloadAccessDescriptionsTable();
		selectFirstAccessDescriptionInTable();
		updateButtonControls();
	}

	private void addPressed() {
		Container container = getTopLevelAncestor();

		DAccessDescriptionChooser dAccessDescriptionChooser = null;

		if (container instanceof JDialog) {
			dAccessDescriptionChooser = new DAccessDescriptionChooser((JDialog) container, title, null);
			dAccessDescriptionChooser.setLocationRelativeTo(container);
			dAccessDescriptionChooser.setVisible(true);
		} else if (container instanceof JFrame) {
			dAccessDescriptionChooser = new DAccessDescriptionChooser((JFrame) container, title, null);
			dAccessDescriptionChooser.setLocationRelativeTo(container);
			dAccessDescriptionChooser.setVisible(true);
		}

		AccessDescription newAccessDescription = dAccessDescriptionChooser.getAccessDescription();

		if (newAccessDescription == null) {
			return;
		}

		accessDescriptions.add(newAccessDescription);

		populate();
		selectAccessDescriptionInTable(newAccessDescription);
	}

	private void removePressed() {
		removeSelectedAccessDescription();
	}

	private void removeSelectedAccessDescription() {
		int selectedRow = jtAccessDescriptions.getSelectedRow();

		if (selectedRow != -1) {
			AccessDescription accessDescription = (AccessDescription) jtAccessDescriptions.getValueAt(selectedRow, 0);

			accessDescriptions.remove(accessDescription);

			reloadAccessDescriptionsTable();
			selectFirstAccessDescriptionInTable();
			updateButtonControls();
		}
	}

	private void editPressed() {
		editSelectedAccessDescription();
	}

	private void maybeEditAccessDescription(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			Point point = new Point(evt.getX(), evt.getY());
			int row = jtAccessDescriptions.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(JAccessDescriptions.this);
					jtAccessDescriptions.setRowSelectionInterval(row, row);
					editSelectedAccessDescription();
				} finally {
					CursorUtil.setCursorFree(JAccessDescriptions.this);
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

			int selectedRow = jtAccessDescriptions.getSelectedRow();

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
		int selectedRow = jtAccessDescriptions.getSelectedRow();

		if (selectedRow != -1) {
			AccessDescription accessDescription = (AccessDescription) jtAccessDescriptions.getValueAt(selectedRow, 0);

			Container container = getTopLevelAncestor();

			DAccessDescriptionChooser dAccessDescriptionChooser = null;

			if (container instanceof JDialog) {
				dAccessDescriptionChooser = new DAccessDescriptionChooser((JDialog) container, title, accessDescription);
				dAccessDescriptionChooser.setLocationRelativeTo(container);
				dAccessDescriptionChooser.setVisible(true);
			} else if (container instanceof JFrame) {
				dAccessDescriptionChooser = new DAccessDescriptionChooser((JFrame) container, title, accessDescription);
				dAccessDescriptionChooser.setLocationRelativeTo(container);
				dAccessDescriptionChooser.setVisible(true);
			}

			AccessDescription newAccessDescription = dAccessDescriptionChooser.getAccessDescription();

			if (newAccessDescription == null) {
				return;
			}

			accessDescriptions.remove(accessDescription);
			accessDescriptions.add(newAccessDescription);

			populate();
			selectAccessDescriptionInTable(newAccessDescription);
		}
	}

	private void selectAccessDescriptionInTable(AccessDescription accessDescription) {
		for (int i = 0; i < jtAccessDescriptions.getRowCount(); i++) {
			if (accessDescription.equals(jtAccessDescriptions.getValueAt(i, 0))) {
				jtAccessDescriptions.changeSelection(i, 0, false, false);
				return;
			}
		}
	}

	private void reloadAccessDescriptionsTable() {
		getAccessDescriptionsTableModel().load(accessDescriptions);
	}

	private void selectFirstAccessDescriptionInTable() {
		if (getAccessDescriptionsTableModel().getRowCount() > 0) {
			jtAccessDescriptions.changeSelection(0, 0, false, false);
		}
	}

	private AccessDescriptionsTableModel getAccessDescriptionsTableModel() {
		return (AccessDescriptionsTableModel) jtAccessDescriptions.getModel();
	}
}
