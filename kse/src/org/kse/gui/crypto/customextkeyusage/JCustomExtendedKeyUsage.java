/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
package org.kse.gui.crypto.customextkeyusage;

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
import java.util.HashSet;
import java.util.ResourceBundle;
import java.util.Set;

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
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.gui.oid.DObjectIdChooser;
import org.kse.utilities.oid.InvalidObjectIdException;
import org.kse.utilities.oid.ObjectIdComparator;
import org.kse.utilities.os.OperatingSystem;

/**
 * Component to edit a set of custom extended key usages.
 *
 */
public class JCustomExtendedKeyUsage extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/customextkeyusage/resources");

	private JPanel jpCustomExtKeyUsageButtons;
	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbRemove;
	private JScrollPane jspCustomExtKeyUsage;
	private JKseTable jtCustomExtKeyUsages;

	private String title;
	private Set<ASN1ObjectIdentifier> objectIds;

	private boolean enabled = true;

	/**
	 * Construct a JCustomExtKeyUsage.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JCustomExtendedKeyUsage(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jbAdd = new JButton(new ImageIcon(Toolkit.getDefaultToolkit()
				.createImage(getClass().getResource("images/add_custom_eku.png"))));
		jbAdd.setMargin(new Insets(2, 2, 0, 0));
		jbAdd.setToolTipText(res.getString("JCustomExtKeyUsage.jbAdd.tooltip"));
		jbAdd.setMnemonic(res.getString("JCustomExtKeyUsage.jbAdd.mnemonic").charAt(0));

		jbAdd.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JCustomExtendedKeyUsage.this);
					addPressed();
				} finally {
					CursorUtil.setCursorFree(JCustomExtendedKeyUsage.this);
				}
			}
		});

		jbEdit = new JButton(new ImageIcon(Toolkit.getDefaultToolkit()
				.createImage(getClass().getResource("images/edit_custom_eku.png"))));
		jbEdit.setMargin(new Insets(2, 2, 0, 0));
		jbEdit.setToolTipText(res.getString("JCustomExtKeyUsage.jbEdit.tooltip"));
		jbEdit.setMnemonic(res.getString("JCustomExtKeyUsage.jbEdit.mnemonic").charAt(0));

		jbEdit.setEnabled(false);

		jbEdit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JCustomExtendedKeyUsage.this);
					editPressed();
				} finally {
					CursorUtil.setCursorFree(JCustomExtendedKeyUsage.this);
				}
			}
		});

		jbRemove = new JButton(new ImageIcon(Toolkit.getDefaultToolkit()
				.createImage(getClass().getResource("images/remove_custom_eku.png"))));
		jbRemove.setMargin(new Insets(2, 2, 0, 0));
		jbRemove.setToolTipText(res.getString("JCustomExtKeyUsage.jbRemove.tooltip"));
		jbRemove.setMnemonic(res.getString("JCustomExtKeyUsage.jbRemove.mnemonic").charAt(0));

		jbRemove.setEnabled(false);

		jbRemove.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JCustomExtendedKeyUsage.this);
					removePressed();
				} finally {
					CursorUtil.setCursorFree(JCustomExtendedKeyUsage.this);
				}
			}
		});

		jpCustomExtKeyUsageButtons = new JPanel();
		jpCustomExtKeyUsageButtons.setLayout(new BoxLayout(jpCustomExtKeyUsageButtons, BoxLayout.Y_AXIS));
		jpCustomExtKeyUsageButtons.add(Box.createVerticalGlue());
		jpCustomExtKeyUsageButtons.add(jbAdd);
		jpCustomExtKeyUsageButtons.add(Box.createVerticalStrut(3));
		jpCustomExtKeyUsageButtons.add(jbEdit);
		jpCustomExtKeyUsageButtons.add(Box.createVerticalStrut(3));
		jpCustomExtKeyUsageButtons.add(jbRemove);
		jpCustomExtKeyUsageButtons.add(Box.createVerticalGlue());

		CustomExtKeyUsageTableModel customExtKeyUsageTableModel = new CustomExtKeyUsageTableModel();
		jtCustomExtKeyUsages = new JKseTable(customExtKeyUsageTableModel);

		TableRowSorter<CustomExtKeyUsageTableModel> sorter = new TableRowSorter<>(customExtKeyUsageTableModel);
		sorter.setComparator(0, new ObjectIdComparator());
		jtCustomExtKeyUsages.setRowSorter(sorter);

		jtCustomExtKeyUsages.setShowGrid(false);
		jtCustomExtKeyUsages.setRowMargin(0);
		jtCustomExtKeyUsages.getColumnModel().setColumnMargin(0);
		jtCustomExtKeyUsages.getTableHeader().setReorderingAllowed(false);
		jtCustomExtKeyUsages.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
		jtCustomExtKeyUsages.setRowHeight(Math.max(18, jtCustomExtKeyUsages.getRowHeight()));

		for (int i = 0; i < jtCustomExtKeyUsages.getColumnCount(); i++) {
			TableColumn column = jtCustomExtKeyUsages.getColumnModel().getColumn(i);
			column.setHeaderRenderer(
					new CustomExtKeyUsageTableHeadRend(jtCustomExtKeyUsages.getTableHeader().getDefaultRenderer()));
			column.setCellRenderer(new CustomExtKeyUsageTableCellRend());
		}

		ListSelectionModel selectionModel = jtCustomExtKeyUsages.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					updateButtonControls();
				}
			}
		});

		jtCustomExtKeyUsages.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeEditCustomExtKeyUsage(evt);
			}
		});

		jtCustomExtKeyUsages.addKeyListener(new KeyAdapter() {
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
						CursorUtil.setCursorBusy(JCustomExtendedKeyUsage.this);
						deleteLastPressed = false;
						removeSelectedCustomExtKeyUsage();
					} finally {
						CursorUtil.setCursorFree(JCustomExtendedKeyUsage.this);
					}
				}
			}

			@Override
			public void keyTyped(KeyEvent evt) {
				// Delete on Mac if back space typed
				if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
					try {
						CursorUtil.setCursorBusy(JCustomExtendedKeyUsage.this);
						removeSelectedCustomExtKeyUsage();
					} finally {
						CursorUtil.setCursorFree(JCustomExtendedKeyUsage.this);
					}
				}
			}
		});

		jspCustomExtKeyUsage = PlatformUtil.createScrollPane(jtCustomExtKeyUsages,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspCustomExtKeyUsage.getViewport().setBackground(jtCustomExtKeyUsages.getBackground());

		this.setLayout(new BorderLayout(5, 5));
		setPreferredSize(new Dimension(250, 150));
		add(jspCustomExtKeyUsage, BorderLayout.CENTER);
		add(jpCustomExtKeyUsageButtons, BorderLayout.EAST);

		populate();
	}

	/**
	 * Get custom extended key usages.
	 *
	 * @return Custom extended key usages
	 */
	public Set<ASN1ObjectIdentifier> getCustomExtKeyUsages() {
		return objectIds;
	}

	/**
	 * Set custom extended key usages.
	 *
	 * @param customExtKeyUsages
	 *            custom extended key usages
	 */
	public void setCustomExtKeyUsages(Set<ASN1ObjectIdentifier> customExtKeyUsages) {
		this.objectIds = customExtKeyUsages;
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
		jspCustomExtKeyUsage.setToolTipText(toolTipText);
		jtCustomExtKeyUsages.setToolTipText(toolTipText);
	}

	private void populate() {
		if (objectIds == null) {
			objectIds = new HashSet<>();
		}

		reloadCustomExtKeyUsageTable();
		selectFirstCustomExtKeyUsageInTable();
		updateButtonControls();
	}

	private void addPressed() {
		Container container = getTopLevelAncestor();

		try {
			DObjectIdChooser dObjectIdChooser = null;

			if (container instanceof JDialog) {
				dObjectIdChooser = new DObjectIdChooser((JDialog) container, title, null);
			} else {
				dObjectIdChooser = new DObjectIdChooser((JFrame) container, title, null);
			}
			dObjectIdChooser.setLocationRelativeTo(container);
			dObjectIdChooser.setVisible(true);

			ASN1ObjectIdentifier newObjectId = dObjectIdChooser.getObjectId();

			if (newObjectId == null) {
				return;
			}

			objectIds.add(newObjectId);
			populate();
			selectCustomExtKeyUsageInTable(newObjectId);
		} catch (InvalidObjectIdException ex) {
			DError dError = null;

			if (container instanceof JDialog) {
				dError = new DError((JDialog) container, ex);
			} else {
				dError = new DError((JFrame) container, ex);
			}

			dError.setLocationRelativeTo(container);
			dError.setVisible(true);
		}
	}

	private void removePressed() {
		removeSelectedCustomExtKeyUsage();
	}

	private void removeSelectedCustomExtKeyUsage() {
		int selectedRow = jtCustomExtKeyUsages.getSelectedRow();

		if (selectedRow != -1) {
			ASN1ObjectIdentifier extKeyUsageOid = (ASN1ObjectIdentifier) jtCustomExtKeyUsages.getValueAt(selectedRow,
					0);

			objectIds.remove(extKeyUsageOid);

			reloadCustomExtKeyUsageTable();
			selectFirstCustomExtKeyUsageInTable();
			updateButtonControls();
		}
	}

	private void editPressed() {
		editSelectedCustomExtKeyUsage();
	}

	private void maybeEditCustomExtKeyUsage(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			Point point = new Point(evt.getX(), evt.getY());
			int row = jtCustomExtKeyUsages.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(JCustomExtendedKeyUsage.this);
					jtCustomExtKeyUsages.setRowSelectionInterval(row, row);
					editSelectedCustomExtKeyUsage();
				} finally {
					CursorUtil.setCursorFree(JCustomExtendedKeyUsage.this);
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

			int selectedRow = jtCustomExtKeyUsages.getSelectedRow();

			if (selectedRow == -1) {
				jbEdit.setEnabled(false);
				jbRemove.setEnabled(false);
			} else {
				jbEdit.setEnabled(true);
				jbRemove.setEnabled(true);
			}
		}
	}

	private void editSelectedCustomExtKeyUsage() {
		int selectedRow = jtCustomExtKeyUsages.getSelectedRow();

		if (selectedRow != -1) {
			ASN1ObjectIdentifier objectId = (ASN1ObjectIdentifier) jtCustomExtKeyUsages.getValueAt(selectedRow, 0);

			Container container = getTopLevelAncestor();

			DObjectIdChooser dObjectIdChooser = null;

			try {
				if (container instanceof JDialog) {
					dObjectIdChooser = new DObjectIdChooser((JDialog) container, title, objectId);
				} else {
					dObjectIdChooser = new DObjectIdChooser((JFrame) container, title, objectId);
				}
			} catch (InvalidObjectIdException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			dObjectIdChooser.setLocationRelativeTo(container);
			dObjectIdChooser.setVisible(true);

			ASN1ObjectIdentifier newObjectId = dObjectIdChooser.getObjectId();

			if (newObjectId == null) {
				return;
			}

			objectIds.remove(objectId);
			objectIds.add(newObjectId);

			populate();
			selectCustomExtKeyUsageInTable(newObjectId);
		}
	}

	private void selectCustomExtKeyUsageInTable(ASN1ObjectIdentifier objectId) {
		for (int i = 0; i < jtCustomExtKeyUsages.getRowCount(); i++) {
			if (objectId.equals(jtCustomExtKeyUsages.getValueAt(i, 0))) {
				jtCustomExtKeyUsages.changeSelection(i, 0, false, false);
				return;
			}
		}
	}

	private void reloadCustomExtKeyUsageTable() {
		getCustomExtKeyUsageTableModel().load(objectIds);
	}

	private void selectFirstCustomExtKeyUsageInTable() {
		if (getCustomExtKeyUsageTableModel().getRowCount() > 0) {
			jtCustomExtKeyUsages.changeSelection(0, 0, false, false);
		}
	}

	private CustomExtKeyUsageTableModel getCustomExtKeyUsageTableModel() {
		return (CustomExtKeyUsageTableModel) jtCustomExtKeyUsages.getModel();
	}

}
