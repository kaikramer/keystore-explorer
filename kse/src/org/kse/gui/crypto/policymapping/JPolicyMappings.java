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
package org.kse.gui.crypto.policymapping;

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

import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.kse.crypto.x509.PolicyMapping;
import org.kse.crypto.x509.PolicyMappingsUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.os.OperatingSystem;

/**
 * Component to edit a set of policy mappings.
 *
 */
public class JPolicyMappings extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/policymapping/resources");

	private JPanel jpPolicyMappingButtons;
	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbRemove;
	private JScrollPane jspPolicyMappings;
	private JKseTable jtPolicyMappings;

	private String title;
	private PolicyMappings policyMappings;
	private boolean enabled = true;

	/**
	 * Construct a JPolicyMappings.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JPolicyMappings(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jbAdd = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JPolicyMappings.jbAdd.image")))));
		jbAdd.setMargin(new Insets(2, 2, 0, 0));
		jbAdd.setToolTipText(res.getString("JPolicyMappings.jbAdd.tooltip"));
		jbAdd.setMnemonic(res.getString("JPolicyMappings.jbAdd.mnemonic").charAt(0));

		jbAdd.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JPolicyMappings.this);
					addPressed();
				} finally {
					CursorUtil.setCursorFree(JPolicyMappings.this);
				}
			}
		});

		jbEdit = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JPolicyMappings.jbEdit.image")))));
		jbEdit.setMargin(new Insets(2, 2, 0, 0));
		jbEdit.setToolTipText(res.getString("JPolicyMappings.jbEdit.tooltip"));
		jbEdit.setMnemonic(res.getString("JPolicyMappings.jbEdit.mnemonic").charAt(0));

		jbEdit.setEnabled(false);

		jbEdit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JPolicyMappings.this);
					editPressed();
				} finally {
					CursorUtil.setCursorFree(JPolicyMappings.this);
				}
			}
		});

		jbRemove = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JPolicyMappings.jbRemove.image")))));
		jbRemove.setMargin(new Insets(2, 2, 0, 0));
		jbRemove.setToolTipText(res.getString("JPolicyMappings.jbRemove.tooltip"));
		jbRemove.setMnemonic(res.getString("JPolicyMappings.jbRemove.mnemonic").charAt(0));

		jbRemove.setEnabled(false);

		jbRemove.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JPolicyMappings.this);
					removePressed();
				} finally {
					CursorUtil.setCursorFree(JPolicyMappings.this);
				}
			}
		});

		jpPolicyMappingButtons = new JPanel();
		jpPolicyMappingButtons.setLayout(new BoxLayout(jpPolicyMappingButtons, BoxLayout.Y_AXIS));
		jpPolicyMappingButtons.add(Box.createVerticalGlue());
		jpPolicyMappingButtons.add(jbAdd);
		jpPolicyMappingButtons.add(Box.createVerticalStrut(3));
		jpPolicyMappingButtons.add(jbEdit);
		jpPolicyMappingButtons.add(Box.createVerticalStrut(3));
		jpPolicyMappingButtons.add(jbRemove);
		jpPolicyMappingButtons.add(Box.createVerticalGlue());

		PolicyMappingsTableModel policyMappingsTableModel = new PolicyMappingsTableModel();
		jtPolicyMappings = new JKseTable(policyMappingsTableModel);

		TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(policyMappingsTableModel);
		sorter.setComparator(0, new PolicyMappingsTableModel.IssuerDomainPolicyComparator());
		sorter.setComparator(1, new PolicyMappingsTableModel.SubjectDomainPolicyComparator());
		jtPolicyMappings.setRowSorter(sorter);

		jtPolicyMappings.setShowGrid(false);
		jtPolicyMappings.setRowMargin(0);
		jtPolicyMappings.getColumnModel().setColumnMargin(0);
		jtPolicyMappings.getTableHeader().setReorderingAllowed(false);
		jtPolicyMappings.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
		jtPolicyMappings.setRowHeight(Math.max(18, jtPolicyMappings.getRowHeight()));

		for (int i = 0; i < jtPolicyMappings.getColumnCount(); i++) {
			TableColumn column = jtPolicyMappings.getColumnModel().getColumn(i);
			column.setHeaderRenderer(new PolicyMappingsTableHeadRend(jtPolicyMappings.getTableHeader()
					.getDefaultRenderer()));
			column.setCellRenderer(new PolicyMappingsTableCellRend());
		}

		ListSelectionModel selectionModel = jtPolicyMappings.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					updateButtonControls();
				}
			}
		});

		jtPolicyMappings.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeEditPolicyMapping(evt);
			}
		});

		jtPolicyMappings.addKeyListener(new KeyAdapter() {
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
						CursorUtil.setCursorBusy(JPolicyMappings.this);
						deleteLastPressed = false;
						removeSelectedPolicyMapping();
					} finally {
						CursorUtil.setCursorFree(JPolicyMappings.this);
					}
				}
			}

			@Override
			public void keyTyped(KeyEvent evt) {
				// Delete on Mac if back space typed
				if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
					try {
						CursorUtil.setCursorBusy(JPolicyMappings.this);
						removeSelectedPolicyMapping();
					} finally {
						CursorUtil.setCursorFree(JPolicyMappings.this);
					}
				}
			}
		});

		jspPolicyMappings = PlatformUtil.createScrollPane(jtPolicyMappings,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspPolicyMappings.getViewport().setBackground(jtPolicyMappings.getBackground());

		this.setLayout(new BorderLayout(5, 5));
		setPreferredSize(new Dimension(400, 150));
		add(jspPolicyMappings, BorderLayout.CENTER);
		add(jpPolicyMappingButtons, BorderLayout.EAST);

		populate();
	}

	/**
	 * Get policy mappings.
	 *
	 * @return Policy mappings
	 */
	public PolicyMappings getPolicyMappings() {
		return policyMappings;
	}

	/**
	 * Set policy mappings.
	 *
	 * @param policyMappings
	 *            Policy mappings
	 */
	public void setPolicyMappings(PolicyMappings policyMappings) {
		this.policyMappings = policyMappings;
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
		jspPolicyMappings.setToolTipText(toolTipText);
		jtPolicyMappings.setToolTipText(toolTipText);
	}

	private void populate() {
		if (policyMappings == null) {
			policyMappings = new PolicyMappings(new CertPolicyId[0], new CertPolicyId[0]);
		}

		reloadPolicyMappingsTable();
		selectFirstPolicyMappingInTable();
		updateButtonControls();
	}

	private void addPressed() {
		Container container = getTopLevelAncestor();

		DPolicyMappingChooser dPolicyMappingChooser = null;

		if (container instanceof JDialog) {
			dPolicyMappingChooser = new DPolicyMappingChooser((JDialog) container, title, null);
			dPolicyMappingChooser.setLocationRelativeTo(container);
			dPolicyMappingChooser.setVisible(true);
		} else if (container instanceof JFrame) {
			dPolicyMappingChooser = new DPolicyMappingChooser((JFrame) container, title, null);
			dPolicyMappingChooser.setLocationRelativeTo(container);
			dPolicyMappingChooser.setVisible(true);
		}

		PolicyMapping newPolicyMapping = dPolicyMappingChooser.getPolicyMapping();

		if (newPolicyMapping == null) {
			return;
		}

		policyMappings = PolicyMappingsUtil.add(newPolicyMapping, policyMappings);

		populate();
		selectPolicyMappingInTable(newPolicyMapping);
	}

	private void removePressed() {
		removeSelectedPolicyMapping();
	}

	private void removeSelectedPolicyMapping() {
		int selectedRow = jtPolicyMappings.getSelectedRow();

		if (selectedRow != -1) {
			PolicyMapping policyMapping = (PolicyMapping) jtPolicyMappings.getValueAt(selectedRow, 0);

			policyMappings = PolicyMappingsUtil.remove(policyMapping, policyMappings);

			reloadPolicyMappingsTable();
			selectFirstPolicyMappingInTable();
			updateButtonControls();
		}
	}

	private void editPressed() {
		editSelectedPolicyMapping();
	}

	private void maybeEditPolicyMapping(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			Point point = new Point(evt.getX(), evt.getY());
			int row = jtPolicyMappings.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(JPolicyMappings.this);
					jtPolicyMappings.setRowSelectionInterval(row, row);
					editSelectedPolicyMapping();
				} finally {
					CursorUtil.setCursorFree(JPolicyMappings.this);
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

			int selectedRow = jtPolicyMappings.getSelectedRow();

			if (selectedRow == -1) {
				jbEdit.setEnabled(false);
				jbRemove.setEnabled(false);
			} else {
				jbEdit.setEnabled(true);
				jbRemove.setEnabled(true);
			}
		}
	}

	private void editSelectedPolicyMapping() {
		int selectedRow = jtPolicyMappings.getSelectedRow();

		if (selectedRow != -1) {
			PolicyMapping policyMapping = (PolicyMapping) jtPolicyMappings.getValueAt(selectedRow, 0);

			Container container = getTopLevelAncestor();

			DPolicyMappingChooser dPolicyMappingChooser = null;

			if (container instanceof JDialog) {
				dPolicyMappingChooser = new DPolicyMappingChooser((JDialog) container, title, policyMapping);
				dPolicyMappingChooser.setLocationRelativeTo(container);
				dPolicyMappingChooser.setVisible(true);
			} else if (container instanceof JFrame) {
				dPolicyMappingChooser = new DPolicyMappingChooser((JFrame) container, title, policyMapping);
				dPolicyMappingChooser.setLocationRelativeTo(container);
				dPolicyMappingChooser.setVisible(true);
			}

			PolicyMapping newPolicyMapping = dPolicyMappingChooser.getPolicyMapping();

			if (newPolicyMapping == null) {
				return;
			}

			policyMappings = PolicyMappingsUtil.remove(policyMapping, policyMappings);
			policyMappings = PolicyMappingsUtil.add(newPolicyMapping, policyMappings);

			populate();
			selectPolicyMappingInTable(newPolicyMapping);
		}
	}

	private void selectPolicyMappingInTable(PolicyMapping policyMapping) {
		for (int i = 0; i < jtPolicyMappings.getRowCount(); i++) {
			if (policyMapping.equals(jtPolicyMappings.getValueAt(i, 0))) {
				jtPolicyMappings.changeSelection(i, 0, false, false);
				return;
			}
		}
	}

	private void reloadPolicyMappingsTable() {
		getPolicyMappingsTableModel().load(policyMappings);
	}

	private void selectFirstPolicyMappingInTable() {
		if (getPolicyMappingsTableModel().getRowCount() > 0) {
			jtPolicyMappings.changeSelection(0, 0, false, false);
		}
	}

	private PolicyMappingsTableModel getPolicyMappingsTableModel() {
		return (PolicyMappingsTableModel) jtPolicyMappings.getModel();
	}

}
