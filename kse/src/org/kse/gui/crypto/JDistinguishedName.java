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
package org.kse.gui.crypto;

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

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.kse.crypto.x509.KseX500NameStyle;
import org.kse.gui.CursorUtil;

/**
 * Component to view or edit a distinguished name.
 *
 */
public class JDistinguishedName extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

	private JTextField jtfDistinguishedName;
	private JButton jbViewEditDistinguishedName;
	private JButton jbClearDistinguishedName;

	private String title;
	private boolean editable;
	private X500Name distinguishedName;

	/**
	 * Construct a JDistinguishedName.
	 *
	 * @param title
	 *            Title of view or edit dialog
	 * @param columns
	 *            Size of text field
	 * @param editable
	 *            Is control editable?
	 */
	public JDistinguishedName(String title, int columns, boolean editable) {
		this.title = title;
		this.editable = editable;
		initComponents(columns);
	}

	private void initComponents(int columns) {
		jtfDistinguishedName = new JTextField(columns);
		jtfDistinguishedName.setEditable(false);

		GridBagConstraints gbcJtfDistinguishedName = new GridBagConstraints();
		gbcJtfDistinguishedName.gridwidth = 1;
		gbcJtfDistinguishedName.gridheight = 1;
		gbcJtfDistinguishedName.gridx = 0;
		gbcJtfDistinguishedName.gridy = 0;
		gbcJtfDistinguishedName.insets = new Insets(0, 0, 0, 5);

		ImageIcon viewEditIcon = new ImageIcon(getClass().getResource(
				"images/view_edit_dn.png"));
		jbViewEditDistinguishedName = new JButton(viewEditIcon);

		if (editable) {
			jbViewEditDistinguishedName.setToolTipText(res
					.getString("JDistinguishedName.jbViewEditDistinguishedName.Edit.tooltip"));
			jbViewEditDistinguishedName.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent evt) {
					try {
						CursorUtil.setCursorBusy(JDistinguishedName.this);
						editDistinguishedName();
					} finally {
						CursorUtil.setCursorFree(JDistinguishedName.this);
					}
				}
			});
		} else {
			jbViewEditDistinguishedName.setToolTipText(res
					.getString("JDistinguishedName.jbViewEditDistinguishedName.View.tooltip"));
			jbViewEditDistinguishedName.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent evt) {
					try {
						CursorUtil.setCursorBusy(JDistinguishedName.this);
						displayDistinguishedName();
					} finally {
						CursorUtil.setCursorFree(JDistinguishedName.this);
					}
				}
			});
		}

		GridBagConstraints gbcJbViewEditDistinguishedName = new GridBagConstraints();
		gbcJbViewEditDistinguishedName.gridwidth = 1;
		gbcJbViewEditDistinguishedName.gridheight = 1;
		gbcJbViewEditDistinguishedName.gridx = 1;
		gbcJbViewEditDistinguishedName.gridy = 0;

		if (editable) {
			gbcJbViewEditDistinguishedName.insets = new Insets(0, 0, 0, 5);
		} else {
			gbcJbViewEditDistinguishedName.insets = new Insets(0, 0, 0, 0);
		}

		ImageIcon clearIcon = new ImageIcon(getClass().getResource(
				"images/clear_dn.png"));
		jbClearDistinguishedName = new JButton(clearIcon);
		jbClearDistinguishedName.setToolTipText(res.getString("JDistinguishedName.jbClearDistinguishedName.tooltip"));
		jbClearDistinguishedName.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JDistinguishedName.this);
					clearDistinguishedName();
				} finally {
					CursorUtil.setCursorFree(JDistinguishedName.this);
				}
			}
		});

		GridBagConstraints gbcJbClearDistinguishedName = new GridBagConstraints();
		gbcJbClearDistinguishedName.gridwidth = 1;
		gbcJbClearDistinguishedName.gridheight = 1;
		gbcJbClearDistinguishedName.gridx = 2;
		gbcJbClearDistinguishedName.gridy = 0;
		gbcJbClearDistinguishedName.insets = new Insets(0, 0, 0, 0);

		setLayout(new GridBagLayout());
		add(jtfDistinguishedName, gbcJtfDistinguishedName);
		add(jbViewEditDistinguishedName, gbcJbViewEditDistinguishedName);

		if (editable) {
			add(jbClearDistinguishedName, gbcJbClearDistinguishedName);
		}

		populate();
	}

	/**
	 * Set distinguished name.
	 *
	 * @param distinguishedName
	 *            Distinguished name
	 */
	public void setDistinguishedName(X500Name distinguishedName) {

		if (distinguishedName == null) {
			this.distinguishedName = new X500Name(KseX500NameStyle.INSTANCE, new RDN[0]);
		} else {
			this.distinguishedName = new X500Name(KseX500NameStyle.INSTANCE, distinguishedName.getRDNs());
		}
		populate();
	}

	/**
	 * Get distinguished name.
	 *
	 * @return Distinguished name
	 */
	public X500Name getDistinguishedName() {
		return distinguishedName;
	}

	/**
	 * Sets whether or not the component is enabled.
	 *
	 * @param enabled
	 *            True if this component should be enabled, false otherwise
	 */
	@Override
	public void setEnabled(boolean enabled) {
		jbViewEditDistinguishedName.setEnabled(enabled);
		jbClearDistinguishedName.setEnabled(enabled);
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
		jtfDistinguishedName.setToolTipText(toolTipText);
	}

	private void populate() {
		if (distinguishedName != null) {
			jtfDistinguishedName.setText(distinguishedName.toString());

			if (editable) {
				jbClearDistinguishedName.setEnabled(true);
			}
		} else {
			jtfDistinguishedName.setText("");

			if (editable) {
				jbClearDistinguishedName.setEnabled(false);
			}
		}

		jtfDistinguishedName.setCaretPosition(0);
	}

	private void displayDistinguishedName() {
		Container container = getTopLevelAncestor();

		if (container instanceof JDialog) {
			DDistinguishedNameChooser dDistinguishedNameChooser = new DDistinguishedNameChooser((JDialog) container,
					title, distinguishedName, false);
			dDistinguishedNameChooser.setLocationRelativeTo(container);
			dDistinguishedNameChooser.setVisible(true);
		} else if (container instanceof JFrame) {
			DDistinguishedNameChooser dDistinguishedNameChooser = new DDistinguishedNameChooser((JFrame) container,
					title, distinguishedName, false);
			dDistinguishedNameChooser.setLocationRelativeTo(container);
			dDistinguishedNameChooser.setVisible(true);
		}
	}

	private void editDistinguishedName() {
		Container container = getTopLevelAncestor();

		DDistinguishedNameChooser dDistinguishedNameChooser = null;

		if (container instanceof JDialog) {
			dDistinguishedNameChooser = new DDistinguishedNameChooser((JDialog) container, title, distinguishedName,
					true);
		} else {
			dDistinguishedNameChooser = new DDistinguishedNameChooser((JFrame) container, title, distinguishedName,
					true);
		}
		dDistinguishedNameChooser.setLocationRelativeTo(container);
		dDistinguishedNameChooser.setVisible(true);

		X500Name newDistinguishedName = dDistinguishedNameChooser.getDistinguishedName();

		if (newDistinguishedName == null) {
			return;
		}

		setDistinguishedName(newDistinguishedName);
	}

	private void clearDistinguishedName() {
		setDistinguishedName(null);
	}
}
