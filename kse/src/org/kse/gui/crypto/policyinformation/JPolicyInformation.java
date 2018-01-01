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
package org.kse.gui.crypto.policyinformation;

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
import java.io.IOException;
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

import org.bouncycastle.asn1.x509.PolicyInformation;
import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.os.OperatingSystem;

/**
 * Component to edit a set of policy information.
 *
 */
public class JPolicyInformation extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/policyinformation/resources");

	private JPanel jpPolicyInformationButtons;
	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbRemove;
	private JScrollPane jspPolicyInformation;
	private JKseTable jtPolicyInformation;

	private String title;
	private List<PolicyInformation> policyInformation;
	private boolean enabled = true;

	/**
	 * Construct a JPolicyInformation.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JPolicyInformation(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jbAdd = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JPolicyInformation.jbAdd.image")))));
		jbAdd.setMargin(new Insets(2, 2, 0, 0));
		jbAdd.setToolTipText(res.getString("JPolicyInformation.jbAdd.tooltip"));
		jbAdd.setMnemonic(res.getString("JPolicyInformation.jbAdd.mnemonic").charAt(0));

		jbAdd.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JPolicyInformation.this);
					addPressed();
				} finally {
					CursorUtil.setCursorFree(JPolicyInformation.this);
				}
			}
		});

		jbEdit = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JPolicyInformation.jbEdit.image")))));
		jbEdit.setMargin(new Insets(2, 2, 0, 0));
		jbEdit.setToolTipText(res.getString("JPolicyInformation.jbEdit.tooltip"));
		jbEdit.setMnemonic(res.getString("JPolicyInformation.jbEdit.mnemonic").charAt(0));

		jbEdit.setEnabled(false);

		jbEdit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JPolicyInformation.this);
					editPressed();
				} finally {
					CursorUtil.setCursorFree(JPolicyInformation.this);
				}
			}
		});

		jbRemove = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JPolicyInformation.jbRemove.image")))));
		jbRemove.setMargin(new Insets(2, 2, 0, 0));
		jbRemove.setToolTipText(res.getString("JPolicyInformation.jbRemove.tooltip"));
		jbRemove.setMnemonic(res.getString("JPolicyInformation.jbRemove.mnemonic").charAt(0));

		jbRemove.setEnabled(false);

		jbRemove.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JPolicyInformation.this);
					removePressed();
				} finally {
					CursorUtil.setCursorFree(JPolicyInformation.this);
				}
			}
		});

		jpPolicyInformationButtons = new JPanel();
		jpPolicyInformationButtons.setLayout(new BoxLayout(jpPolicyInformationButtons, BoxLayout.Y_AXIS));
		jpPolicyInformationButtons.add(Box.createVerticalGlue());
		jpPolicyInformationButtons.add(jbAdd);
		jpPolicyInformationButtons.add(Box.createVerticalStrut(3));
		jpPolicyInformationButtons.add(jbEdit);
		jpPolicyInformationButtons.add(Box.createVerticalStrut(3));
		jpPolicyInformationButtons.add(jbRemove);
		jpPolicyInformationButtons.add(Box.createVerticalGlue());

		PolicyInformationTableModel policyInformationTableModel = new PolicyInformationTableModel();
		jtPolicyInformation = new JKseTable(policyInformationTableModel);

		TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(policyInformationTableModel);
		sorter.setComparator(0, new PolicyInformationTableModel.PolicyInformationComparator());
		jtPolicyInformation.setRowSorter(sorter);

		jtPolicyInformation.setShowGrid(false);
		jtPolicyInformation.setRowMargin(0);
		jtPolicyInformation.getColumnModel().setColumnMargin(0);
		jtPolicyInformation.getTableHeader().setReorderingAllowed(false);
		jtPolicyInformation.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
		jtPolicyInformation.setRowHeight(Math.max(18, jtPolicyInformation.getRowHeight()));

		for (int i = 0; i < jtPolicyInformation.getColumnCount(); i++) {
			TableColumn column = jtPolicyInformation.getColumnModel().getColumn(i);
			column.setHeaderRenderer(new PolicyInformationTableHeadRend(jtPolicyInformation.getTableHeader()
					.getDefaultRenderer()));
			column.setCellRenderer(new PolicyInformationTableCellRend());
		}

		ListSelectionModel selectionModel = jtPolicyInformation.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					updateButtonControls();
				}
			}
		});

		jtPolicyInformation.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeEditPolicyInformation(evt);
			}
		});

		jtPolicyInformation.addKeyListener(new KeyAdapter() {
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
						CursorUtil.setCursorBusy(JPolicyInformation.this);
						deleteLastPressed = false;
						removeSelectedPolicyInformation();
					} finally {
						CursorUtil.setCursorFree(JPolicyInformation.this);
					}
				}
			}

			@Override
			public void keyTyped(KeyEvent evt) {
				// Delete on Mac if back space typed
				if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
					try {
						CursorUtil.setCursorBusy(JPolicyInformation.this);
						removeSelectedPolicyInformation();
					} finally {
						CursorUtil.setCursorFree(JPolicyInformation.this);
					}
				}
			}
		});

		jspPolicyInformation = PlatformUtil.createScrollPane(jtPolicyInformation,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspPolicyInformation.getViewport().setBackground(jtPolicyInformation.getBackground());

		this.setLayout(new BorderLayout(5, 5));
		setPreferredSize(new Dimension(250, 150));
		add(jspPolicyInformation, BorderLayout.CENTER);
		add(jpPolicyInformationButtons, BorderLayout.EAST);

		populate();
	}

	/**
	 * Get policy information.
	 *
	 * @return Policy information
	 */
	public List<PolicyInformation> getPolicyInformation() {
		return policyInformation;
	}

	/**
	 * Set policy information.
	 *
	 * @param policyInformation
	 *            Policy information
	 */
	public void setPolicyInformation(List<PolicyInformation> policyInformation) {
		this.policyInformation = policyInformation;
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
		jspPolicyInformation.setToolTipText(toolTipText);
		jtPolicyInformation.setToolTipText(toolTipText);
	}

	private void populate() {
		if (policyInformation == null) {
			policyInformation = new ArrayList<PolicyInformation>();
		}

		reloadPolicyInformationTable();
		selectFirstPolicyInformationInTable();
		updateButtonControls();
	}

	private void addPressed() {
		Container container = getTopLevelAncestor();

		try {
			DPolicyInformationChooser dPolicyInformationChooser = null;

			if (container instanceof JDialog) {
				dPolicyInformationChooser = new DPolicyInformationChooser((JDialog) container, title, null);
				dPolicyInformationChooser.setLocationRelativeTo(container);
				dPolicyInformationChooser.setVisible(true);
			} else if (container instanceof JFrame) {
				dPolicyInformationChooser = new DPolicyInformationChooser((JFrame) container, title, null);
				dPolicyInformationChooser.setLocationRelativeTo(container);
				dPolicyInformationChooser.setVisible(true);
			}

			PolicyInformation newPolicyInfo = dPolicyInformationChooser.getPolicyInformation();

			if (newPolicyInfo == null) {
				return;
			}

			policyInformation.add(newPolicyInfo);

			populate();
			selectPolicyInformationInTable(newPolicyInfo);
		} catch (IOException ex) {
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
		removeSelectedPolicyInformation();
	}

	private void removeSelectedPolicyInformation() {
		int selectedRow = jtPolicyInformation.getSelectedRow();

		if (selectedRow != -1) {
			PolicyInformation policyInfo = (PolicyInformation) jtPolicyInformation.getValueAt(selectedRow, 0);

			policyInformation.remove(policyInfo);

			reloadPolicyInformationTable();
			selectFirstPolicyInformationInTable();
			updateButtonControls();
		}
	}

	private void editPressed() {
		editSelectedPolicyInformation();
	}

	private void maybeEditPolicyInformation(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			Point point = new Point(evt.getX(), evt.getY());
			int row = jtPolicyInformation.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(JPolicyInformation.this);
					jtPolicyInformation.setRowSelectionInterval(row, row);
					editSelectedPolicyInformation();
				} finally {
					CursorUtil.setCursorFree(JPolicyInformation.this);
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

			int selectedRow = jtPolicyInformation.getSelectedRow();

			if (selectedRow == -1) {
				jbEdit.setEnabled(false);
				jbRemove.setEnabled(false);
			} else {
				jbEdit.setEnabled(true);
				jbRemove.setEnabled(true);
			}
		}
	}

	private void editSelectedPolicyInformation() {
		int selectedRow = jtPolicyInformation.getSelectedRow();

		if (selectedRow != -1) {
			PolicyInformation policyInfo = (PolicyInformation) jtPolicyInformation.getValueAt(selectedRow, 0);

			Container container = getTopLevelAncestor();

			try {
				DPolicyInformationChooser dPolicyNameChooser = null;

				if (container instanceof JDialog) {
					dPolicyNameChooser = new DPolicyInformationChooser((JDialog) container, title, policyInfo);
					dPolicyNameChooser.setLocationRelativeTo(container);
					dPolicyNameChooser.setVisible(true);
				} else if (container instanceof JFrame) {
					dPolicyNameChooser = new DPolicyInformationChooser((JFrame) container, title, policyInfo);
					dPolicyNameChooser.setLocationRelativeTo(container);
					dPolicyNameChooser.setVisible(true);
				}

				PolicyInformation newPolicyInfo = dPolicyNameChooser.getPolicyInformation();

				if (newPolicyInfo == null) {
					return;
				}

				policyInformation.remove(policyInfo);
				policyInformation.add(newPolicyInfo);

				populate();
				selectPolicyInformationInTable(newPolicyInfo);
			} catch (IOException ex) {
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
	}

	private void selectPolicyInformationInTable(PolicyInformation policyInfo) {
		for (int i = 0; i < jtPolicyInformation.getRowCount(); i++) {
			if (policyInfo.equals(jtPolicyInformation.getValueAt(i, 0))) {
				jtPolicyInformation.changeSelection(i, 0, false, false);
				return;
			}
		}
	}

	private void reloadPolicyInformationTable() {
		getPolicyInformationTableModel().load(policyInformation);
	}

	private void selectFirstPolicyInformationInTable() {
		if (getPolicyInformationTableModel().getRowCount() > 0) {
			jtPolicyInformation.changeSelection(0, 0, false, false);
		}
	}

	private PolicyInformationTableModel getPolicyInformationTableModel() {
		return (PolicyInformationTableModel) jtPolicyInformation.getModel();
	}
}
