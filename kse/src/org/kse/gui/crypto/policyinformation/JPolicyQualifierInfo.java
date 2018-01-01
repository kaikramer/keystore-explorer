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

import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.os.OperatingSystem;

/**
 * Component to edit a set of policy qualifier info.
 *
 */
public class JPolicyQualifierInfo extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/policyinformation/resources");

	private JPanel jpPolicyQualifierInfoButtons;
	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbRemove;
	private JScrollPane jspPolicyQualifierInfo;
	private JKseTable jtPolicyQualifierInfo;

	private String title;
	private List<PolicyQualifierInfo> policyQualifierInfo;
	private boolean enabled = true;

	/**
	 * Construct a JPolicyQualifierInfo.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JPolicyQualifierInfo(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jbAdd = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JPolicyQualifierInfo.jbAdd.image")))));
		jbAdd.setMargin(new Insets(2, 2, 0, 0));
		jbAdd.setToolTipText(res.getString("JPolicyQualifierInfo.jbAdd.tooltip"));
		jbAdd.setMnemonic(res.getString("JPolicyQualifierInfo.jbAdd.mnemonic").charAt(0));

		jbAdd.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JPolicyQualifierInfo.this);
					addPressed();
				} finally {
					CursorUtil.setCursorFree(JPolicyQualifierInfo.this);
				}
			}
		});

		jbEdit = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JPolicyQualifierInfo.jbEdit.image")))));
		jbEdit.setMargin(new Insets(2, 2, 0, 0));
		jbEdit.setToolTipText(res.getString("JPolicyQualifierInfo.jbEdit.tooltip"));
		jbEdit.setMnemonic(res.getString("JPolicyQualifierInfo.jbEdit.mnemonic").charAt(0));

		jbEdit.setEnabled(false);

		jbEdit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JPolicyQualifierInfo.this);
					editPressed();
				} finally {
					CursorUtil.setCursorFree(JPolicyQualifierInfo.this);
				}
			}
		});

		jbRemove = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("JPolicyQualifierInfo.jbRemove.image")))));
		jbRemove.setMargin(new Insets(2, 2, 0, 0));
		jbRemove.setToolTipText(res.getString("JPolicyQualifierInfo.jbRemove.tooltip"));
		jbRemove.setMnemonic(res.getString("JPolicyQualifierInfo.jbRemove.mnemonic").charAt(0));

		jbRemove.setEnabled(false);

		jbRemove.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JPolicyQualifierInfo.this);
					removePressed();
				} finally {
					CursorUtil.setCursorFree(JPolicyQualifierInfo.this);
				}
			}
		});

		jpPolicyQualifierInfoButtons = new JPanel();
		jpPolicyQualifierInfoButtons.setLayout(new BoxLayout(jpPolicyQualifierInfoButtons, BoxLayout.Y_AXIS));
		jpPolicyQualifierInfoButtons.add(Box.createVerticalGlue());
		jpPolicyQualifierInfoButtons.add(jbAdd);
		jpPolicyQualifierInfoButtons.add(Box.createVerticalStrut(3));
		jpPolicyQualifierInfoButtons.add(jbEdit);
		jpPolicyQualifierInfoButtons.add(Box.createVerticalStrut(3));
		jpPolicyQualifierInfoButtons.add(jbRemove);
		jpPolicyQualifierInfoButtons.add(Box.createVerticalGlue());

		PolicyQualifierInfoTableModel policyQualifierInfoTableModel = new PolicyQualifierInfoTableModel();
		jtPolicyQualifierInfo = new JKseTable(policyQualifierInfoTableModel);

		TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(policyQualifierInfoTableModel);
		sorter.setComparator(0, new PolicyQualifierInfoTableModel.PolicyQualifierInfoComparator());
		jtPolicyQualifierInfo.setRowSorter(sorter);

		jtPolicyQualifierInfo.setShowGrid(false);
		jtPolicyQualifierInfo.setRowMargin(0);
		jtPolicyQualifierInfo.getColumnModel().setColumnMargin(0);
		jtPolicyQualifierInfo.getTableHeader().setReorderingAllowed(false);
		jtPolicyQualifierInfo.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
		jtPolicyQualifierInfo.setRowHeight(Math.max(18, jtPolicyQualifierInfo.getRowHeight()));

		for (int i = 0; i < jtPolicyQualifierInfo.getColumnCount(); i++) {
			TableColumn column = jtPolicyQualifierInfo.getColumnModel().getColumn(i);
			column.setHeaderRenderer(new PolicyQualifierInfoTableHeadRend(jtPolicyQualifierInfo.getTableHeader()
					.getDefaultRenderer()));
			column.setCellRenderer(new PolicyQualifierInfoTableCellRend());
		}

		ListSelectionModel selectionModel = jtPolicyQualifierInfo.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					updateButtonControls();
				}
			}
		});

		jtPolicyQualifierInfo.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeEditPolicyQualifierInfo(evt);
			}
		});

		jtPolicyQualifierInfo.addKeyListener(new KeyAdapter() {
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
						CursorUtil.setCursorBusy(JPolicyQualifierInfo.this);
						deleteLastPressed = false;
						removeSelectedPolicyQualifierInfo();
					} finally {
						CursorUtil.setCursorFree(JPolicyQualifierInfo.this);
					}
				}
			}

			@Override
			public void keyTyped(KeyEvent evt) {
				// Delete on Mac if back space typed
				if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
					try {
						CursorUtil.setCursorBusy(JPolicyQualifierInfo.this);
						removeSelectedPolicyQualifierInfo();
					} finally {
						CursorUtil.setCursorFree(JPolicyQualifierInfo.this);
					}
				}
			}
		});

		jspPolicyQualifierInfo = PlatformUtil.createScrollPane(jtPolicyQualifierInfo,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspPolicyQualifierInfo.getViewport().setBackground(jtPolicyQualifierInfo.getBackground());

		this.setLayout(new BorderLayout(5, 5));
		setPreferredSize(new Dimension(400, 150));
		add(jspPolicyQualifierInfo, BorderLayout.CENTER);
		add(jpPolicyQualifierInfoButtons, BorderLayout.EAST);

		populate();
	}

	/**
	 * Get policy qualifier info.
	 *
	 * @return Policy qualifier info
	 */
	public List<PolicyQualifierInfo> getPolicyQualifierInfo() {
		return policyQualifierInfo;
	}

	/**
	 * Set policy qualifier info.
	 *
	 * @param policyQualifierInfo
	 *            Policy qualifier info
	 */
	public void setPolicyQualifierInfo(List<PolicyQualifierInfo> policyQualifierInfo) {
		this.policyQualifierInfo = policyQualifierInfo;
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
		jspPolicyQualifierInfo.setToolTipText(toolTipText);
		jtPolicyQualifierInfo.setToolTipText(toolTipText);
	}

	private void populate() {
		if (policyQualifierInfo == null) {
			policyQualifierInfo = new ArrayList<PolicyQualifierInfo>();
		}

		reloadPolicyQualifierInfoTable();
		selectFirstPolicyQualifierInfoInTable();
		updateButtonControls();
	}

	private void addPressed() {
		Container container = getTopLevelAncestor();

		try {
			DPolicyQualifierInfoChooser dPolicyQualifierInfoChooser = null;

			if (container instanceof JDialog) {
				dPolicyQualifierInfoChooser = new DPolicyQualifierInfoChooser((JDialog) container, title, null);
				dPolicyQualifierInfoChooser.setLocationRelativeTo(container);
				dPolicyQualifierInfoChooser.setVisible(true);
			} else if (container instanceof JFrame) {
				dPolicyQualifierInfoChooser = new DPolicyQualifierInfoChooser((JFrame) container, title, null);
				dPolicyQualifierInfoChooser.setLocationRelativeTo(container);
				dPolicyQualifierInfoChooser.setVisible(true);
			}

			PolicyQualifierInfo newPolicyQualifierInfo = dPolicyQualifierInfoChooser.getPolicyQualifierInfo();

			if (newPolicyQualifierInfo == null) {
				return;
			}

			policyQualifierInfo.add(newPolicyQualifierInfo);

			populate();
			selectPolicyQualifierInfoInTable(newPolicyQualifierInfo);
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
		removeSelectedPolicyQualifierInfo();
	}

	private void removeSelectedPolicyQualifierInfo() {
		int selectedRow = jtPolicyQualifierInfo.getSelectedRow();

		if (selectedRow != -1) {
			PolicyQualifierInfo policyQualInfo = (PolicyQualifierInfo) jtPolicyQualifierInfo.getValueAt(selectedRow, 0);

			policyQualifierInfo.remove(policyQualInfo);

			reloadPolicyQualifierInfoTable();
			selectFirstPolicyQualifierInfoInTable();
			updateButtonControls();
		}
	}

	private void editPressed() {
		editSelectedPolicQualifier();
	}

	private void maybeEditPolicyQualifierInfo(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			Point point = new Point(evt.getX(), evt.getY());
			int row = jtPolicyQualifierInfo.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(JPolicyQualifierInfo.this);
					jtPolicyQualifierInfo.setRowSelectionInterval(row, row);
					editSelectedPolicQualifier();
				} finally {
					CursorUtil.setCursorFree(JPolicyQualifierInfo.this);
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

			int selectedRow = jtPolicyQualifierInfo.getSelectedRow();

			if (selectedRow == -1) {
				jbEdit.setEnabled(false);
				jbRemove.setEnabled(false);
			} else {
				jbEdit.setEnabled(true);
				jbRemove.setEnabled(true);
			}
		}
	}

	private void editSelectedPolicQualifier() {
		int selectedRow = jtPolicyQualifierInfo.getSelectedRow();

		if (selectedRow != -1) {
			PolicyQualifierInfo policyQualInfo = (PolicyQualifierInfo) jtPolicyQualifierInfo.getValueAt(selectedRow, 0);

			Container container = getTopLevelAncestor();

			try {
				DPolicyQualifierInfoChooser dPolicyQualifierInfoChooser = null;

				if (container instanceof JDialog) {
					dPolicyQualifierInfoChooser = new DPolicyQualifierInfoChooser((JDialog) container, title,
							policyQualInfo);
					dPolicyQualifierInfoChooser.setLocationRelativeTo(container);
					dPolicyQualifierInfoChooser.setVisible(true);
				} else if (container instanceof JFrame) {
					dPolicyQualifierInfoChooser = new DPolicyQualifierInfoChooser((JFrame) container, title,
							policyQualInfo);
					dPolicyQualifierInfoChooser.setLocationRelativeTo(container);
					dPolicyQualifierInfoChooser.setVisible(true);
				}

				PolicyQualifierInfo newPolicyQualifierInfo = dPolicyQualifierInfoChooser.getPolicyQualifierInfo();

				if (newPolicyQualifierInfo == null) {
					return;
				}

				policyQualifierInfo.remove(policyQualInfo);
				policyQualifierInfo.add(newPolicyQualifierInfo);

				populate();
				selectPolicyQualifierInfoInTable(newPolicyQualifierInfo);
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

	private void selectPolicyQualifierInfoInTable(PolicyQualifierInfo policyQualInfo) {
		for (int i = 0; i < jtPolicyQualifierInfo.getRowCount(); i++) {
			if (policyQualInfo.equals(jtPolicyQualifierInfo.getValueAt(i, 0))) {
				jtPolicyQualifierInfo.changeSelection(i, 0, false, false);
				return;
			}
		}
	}

	private void reloadPolicyQualifierInfoTable() {
		getPolicyQualifierInfoTableModel().load(policyQualifierInfo);
	}

	private void selectFirstPolicyQualifierInfoInTable() {
		if (getPolicyQualifierInfoTableModel().getRowCount() > 0) {
			jtPolicyQualifierInfo.changeSelection(0, 0, false, false);
		}
	}

	private PolicyQualifierInfoTableModel getPolicyQualifierInfoTableModel() {
		return (PolicyQualifierInfoTableModel) jtPolicyQualifierInfo.getModel();
	}
}
