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
package org.kse.gui.oid;

import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.gui.CursorUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.oid.InvalidObjectIdException;
import org.kse.utilities.oid.ObjectIdUtil;

/**
 * Component to edit an object identifier.
 *
 */
public class JObjectId extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/oid/resources");

	private JTextField jtfObjectId;
	private JButton jbEditObjectId;
	private JButton jbClearObjectId;

	private String title;
	private ASN1ObjectIdentifier objectId;

	/**
	 * Construct a JObjectId.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JObjectId(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jtfObjectId = new JTextField(25);
		jtfObjectId.setEditable(false);

		GridBagConstraints gbc_jtfObjectId = new GridBagConstraints();
		gbc_jtfObjectId.gridwidth = 1;
		gbc_jtfObjectId.gridheight = 1;
		gbc_jtfObjectId.gridx = 0;
		gbc_jtfObjectId.gridy = 0;
		gbc_jtfObjectId.insets = new Insets(0, 0, 0, 5);

		ImageIcon editIcon = new ImageIcon(getClass().getResource(res.getString("JObjectId.jbEditObjectId.image")));
		jbEditObjectId = new JButton(editIcon);
		jbEditObjectId.setToolTipText(res.getString("JObjectId.jbEditObjectId.tooltip"));
		jbEditObjectId.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JObjectId.this);
					editObjectId();
				} finally {
					CursorUtil.setCursorFree(JObjectId.this);
				}
			}
		});

		GridBagConstraints gbc_jbEditObjectId = new GridBagConstraints();
		gbc_jbEditObjectId.gridwidth = 1;
		gbc_jbEditObjectId.gridheight = 1;
		gbc_jbEditObjectId.gridx = 1;
		gbc_jbEditObjectId.gridy = 0;
		gbc_jbEditObjectId.insets = new Insets(0, 0, 0, 5);

		ImageIcon clearIcon = new ImageIcon(getClass().getResource(res.getString("JObjectId.jbClearObjectId.image")));
		jbClearObjectId = new JButton(clearIcon);
		jbClearObjectId.setToolTipText(res.getString("JObjectId.jbClearObjectId.tooltip"));
		jbClearObjectId.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JObjectId.this);
					clearObjectId();
				} finally {
					CursorUtil.setCursorFree(JObjectId.this);
				}
			}
		});

		GridBagConstraints gbc_jbClearObjectId = new GridBagConstraints();
		gbc_jbClearObjectId.gridwidth = 1;
		gbc_jbClearObjectId.gridheight = 1;
		gbc_jbClearObjectId.gridx = 2;
		gbc_jbClearObjectId.gridy = 0;
		gbc_jbClearObjectId.insets = new Insets(0, 0, 0, 0);

		setLayout(new GridBagLayout());
		add(jtfObjectId, gbc_jtfObjectId);
		add(jbEditObjectId, gbc_jbEditObjectId);
		add(jbClearObjectId, gbc_jbClearObjectId);

		populate();
	}

	/**
	 * Get object identifier.
	 *
	 * @return Object identifer, or null if none chosen
	 */
	public ASN1ObjectIdentifier getObjectId() {
		return objectId;
	}

	/**
	 * Set object identifier.
	 *
	 * @param objectId
	 *            Object identifier
	 */
	public void setObjectId(ASN1ObjectIdentifier objectId) {
		this.objectId = objectId;
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
		jbEditObjectId.setEnabled(enabled);
		jbClearObjectId.setEnabled(enabled);
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
		jtfObjectId.setToolTipText(toolTipText);
	}

	private void populate() {
		if (objectId != null) {
			jtfObjectId.setText(ObjectIdUtil.toString(objectId));
			jbClearObjectId.setEnabled(true);
		} else {
			jtfObjectId.setText("");
			jbClearObjectId.setEnabled(false);
		}

		jtfObjectId.setCaretPosition(0);
	}

	private void editObjectId() {
		Container container = getTopLevelAncestor();

		try {
			DObjectIdChooser dObjectIdChooser = null;

			if (container instanceof JDialog) {
				dObjectIdChooser = new DObjectIdChooser((JDialog) container, title, objectId);
				dObjectIdChooser.setLocationRelativeTo(container);
				dObjectIdChooser.setVisible(true);
			} else if (container instanceof JFrame) {
				dObjectIdChooser = new DObjectIdChooser((JFrame) container, title, objectId);
				dObjectIdChooser.setLocationRelativeTo(container);
				dObjectIdChooser.setVisible(true);
			}

			ASN1ObjectIdentifier newObjectId = dObjectIdChooser.getObjectId();

			if (newObjectId == null) {
				return;
			}

			setObjectId(newObjectId);
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

	private void clearObjectId() {
		setObjectId(null);
	}
}
