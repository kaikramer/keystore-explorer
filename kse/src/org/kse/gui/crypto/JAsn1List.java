/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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

import java.awt.BorderLayout;
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
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.kse.gui.CursorUtil;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.os.OperatingSystem;

/**
 * Component to edit a ASN1Sequence
 *
 */
public class JAsn1List<T extends ASN1Object> extends JPanel {

	private static final long serialVersionUID = 1L;

	private JPanel jpAsn1ObjectButtons;
	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbRemove;
	private JScrollPane jspAsn1Object;
	private JKseTable jtAsn1Object;
	
	private String messagesPreffix;

	private boolean enabled = true;

	private ResourceBundle res;

	/**
	 * Construct a JGeneralSubtrees.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	
	public JAsn1List(String messagesPreffix, ResourceBundle bundle) {
		this.messagesPreffix = messagesPreffix;
		this.res = bundle; 
		initComponents();
	}

	private void initComponents() {
		jbAdd = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString(messagesPreffix + ".jbAdd.image")))));
		jbAdd.setMargin(new Insets(2, 2, 0, 0));
		jbAdd.setToolTipText(res.getString(messagesPreffix + ".jbAdd.tooltip"));
		jbAdd.setMnemonic(res.getString(messagesPreffix + ".jbAdd.mnemonic").charAt(0));

		jbAdd.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JAsn1List.this);
					addPressed();
				} finally {
					CursorUtil.setCursorFree(JAsn1List.this);
				}
			}
		});

		jbEdit = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString(messagesPreffix + ".jbEdit.image")))));
		jbEdit.setMargin(new Insets(2, 2, 0, 0));
		jbEdit.setToolTipText(res.getString(messagesPreffix + ".jbEdit.tooltip"));
		jbEdit.setMnemonic(res.getString(messagesPreffix + ".jbEdit.mnemonic").charAt(0));

		jbEdit.setEnabled(false);

		jbEdit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JAsn1List.this);
					editPressed();
				} finally {
					CursorUtil.setCursorFree(JAsn1List.this);
				}
			}
		});

		jbRemove = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString(messagesPreffix + ".jbRemove.image")))));
		jbRemove.setMargin(new Insets(2, 2, 0, 0));
		jbRemove.setToolTipText(res.getString(messagesPreffix + ".jbRemove.tooltip"));
		jbRemove.setMnemonic(res.getString(messagesPreffix + ".jbRemove.mnemonic").charAt(0));

		jbRemove.setEnabled(false);

		jbRemove.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JAsn1List.this);
					removeSelectedObject();
				} finally {
					CursorUtil.setCursorFree(JAsn1List.this);
				}
			}
		});

		jpAsn1ObjectButtons = new JPanel();
		jpAsn1ObjectButtons.setLayout(new BoxLayout(jpAsn1ObjectButtons, BoxLayout.Y_AXIS));
		jpAsn1ObjectButtons.add(Box.createVerticalGlue());
		jpAsn1ObjectButtons.add(jbAdd);
		jpAsn1ObjectButtons.add(Box.createVerticalStrut(3));
		jpAsn1ObjectButtons.add(jbEdit);
		jpAsn1ObjectButtons.add(Box.createVerticalStrut(3));
		jpAsn1ObjectButtons.add(jbRemove);
		jpAsn1ObjectButtons.add(Box.createVerticalGlue());

		jtAsn1Object = createTable();

		ListSelectionModel selectionModel = jtAsn1Object.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					updateButtonControls();
				}
			}
		});

		jtAsn1Object.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeEditAsn1Object(evt);
			}
		});

		jtAsn1Object.addKeyListener(new KeyAdapter() {
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
						CursorUtil.setCursorBusy(JAsn1List.this);
						deleteLastPressed = false;
						removeSelectedObject();
					} finally {
						CursorUtil.setCursorFree(JAsn1List.this);
					}
				}
			}

			@Override
			public void keyTyped(KeyEvent evt) {
				// Delete on Mac if back space typed
				if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
					try {
						CursorUtil.setCursorBusy(JAsn1List.this);
						removeSelectedObject();
					} finally {
						CursorUtil.setCursorFree(JAsn1List.this);
					}
				}
			}
		});

		jspAsn1Object = PlatformUtil.createScrollPane(jtAsn1Object,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspAsn1Object.getViewport().setBackground(jtAsn1Object.getBackground());

		this.setLayout(new BorderLayout(5, 5));
		setPreferredSize(new Dimension(400, 150));
		add(jspAsn1Object, BorderLayout.CENTER);
		add(jpAsn1ObjectButtons, BorderLayout.EAST);

		populate();
	}

	/**
	 * Get asn1 object.
	 *
	 * @return ASN1 Object
	 */
	public ASN1Sequence getObject() {
		ASN1Object[] asn1Objects = new ASN1Object[getObjectTableModel().getRowCount()];
		return new DERSequence(getObjectTableModel().getData().toArray(asn1Objects));
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
		jspAsn1Object.setToolTipText(toolTipText);
		jtAsn1Object.setToolTipText(toolTipText);
	}

	public void populate() {
		reloadObjectsTable();
		selectFirstObjectInTable();
		updateButtonControls();
	}

	public void removeSelectedObject() {
		int selectedRow = jtAsn1Object.getSelectedRow();

		if (selectedRow != -1) {
			getObjectTableModel().removeRow(selectedRow);

			reloadObjectsTable();
			selectFirstObjectInTable();
			updateButtonControls();
		}
	}

	public void editPressed() {
		editSelectedObject();
	}

	public void maybeEditAsn1Object(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			Point point = new Point(evt.getX(), evt.getY());
			int row = jtAsn1Object.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(JAsn1List.this);
					jtAsn1Object.setRowSelectionInterval(row, row);
					editSelectedObject();
				} finally {
					CursorUtil.setCursorFree(JAsn1List.this);
				}
			}
		}
	}

	public void updateButtonControls() {
		if (!enabled) {
			jbAdd.setEnabled(false);
			jbEdit.setEnabled(false);
			jbRemove.setEnabled(false);
		} else {
			jbAdd.setEnabled(true);

			int selectedRow = jtAsn1Object.getSelectedRow();

			if (selectedRow == -1) {
				jbEdit.setEnabled(false);
				jbRemove.setEnabled(false);
			} else {
				jbEdit.setEnabled(true);
				jbRemove.setEnabled(true);
			}
		}
	}

	public void editSelectedObject() {
		int selectedRow = jtAsn1Object.getSelectedRow();

		if (selectedRow != -1) {
			T object = getObjectTableModel().getRow(selectedRow);

			T newObject = editObject(object);

			if (newObject == null) {
				return;
			}

			getObjectTableModel().removeRow(selectedRow);
			getObjectTableModel().addRow(selectedRow, newObject);

			populate();
			selectObjectInTable(newObject);
		}
	}

	public void selectObjectInTable(T object) {
		for (int i = 0; i < jtAsn1Object.getRowCount(); i++) {
			if (object.equals(jtAsn1Object.getValueAt(i, 0))) {
				jtAsn1Object.changeSelection(i, 0, false, false);
				return;
			}
		}
	}

	public void selectFirstObjectInTable() {
		if (getObjectTableModel().getRowCount() > 0) {
			jtAsn1Object.changeSelection(0, 0, false, false);
		}
	}

	@SuppressWarnings("unchecked")
	public GeneralTableModel<T> getObjectTableModel() {
		return jtAsn1Object == null? null: (GeneralTableModel<T>) jtAsn1Object.getModel();
	}

	protected JKseTable createTable() {
		return new JKseTable(getObjectTableModel());
	}

	public void reloadObjectsTable() {
		getObjectTableModel().fireTableDataChanged();
	}

	public void addPressed() {
	}

	public T editObject(T obj) {
		return null;
	}
}
