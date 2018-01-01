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

import org.bouncycastle.asn1.x509.GeneralName;
import org.kse.crypto.x509.GeneralNameUtil;
import org.kse.gui.CursorUtil;

/**
 * Component to edit a general name.
 *
 */
public class JGeneralName extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/generalname/resources");

	private JTextField jtfGeneralName;
	private JButton jbEditGeneralName;
	private JButton jbClearGeneralName;

	private String title;
	private GeneralName generalName;

	/**
	 * Construct a JGeneralName.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JGeneralName(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jtfGeneralName = new JTextField(40);
		jtfGeneralName.setEditable(false);

		GridBagConstraints gbc_jtfGeneralName = new GridBagConstraints();
		gbc_jtfGeneralName.gridwidth = 1;
		gbc_jtfGeneralName.gridheight = 1;
		gbc_jtfGeneralName.gridx = 0;
		gbc_jtfGeneralName.gridy = 0;
		gbc_jtfGeneralName.insets = new Insets(0, 0, 0, 5);

		ImageIcon editIcon = new ImageIcon(getClass()
				.getResource(res.getString("JGeneralName.jbEditGeneralName.image")));
		jbEditGeneralName = new JButton(editIcon);
		jbEditGeneralName.setToolTipText(res.getString("JGeneralName.jbEditGeneralName.tooltip"));
		jbEditGeneralName.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JGeneralName.this);
					editGeneralName();
				} finally {
					CursorUtil.setCursorFree(JGeneralName.this);
				}
			}
		});

		GridBagConstraints gbc_jbEditGeneralName = new GridBagConstraints();
		gbc_jbEditGeneralName.gridwidth = 1;
		gbc_jbEditGeneralName.gridheight = 1;
		gbc_jbEditGeneralName.gridx = 1;
		gbc_jbEditGeneralName.gridy = 0;
		gbc_jbEditGeneralName.insets = new Insets(0, 0, 0, 5);

		ImageIcon clearIcon = new ImageIcon(getClass().getResource(
				res.getString("JGeneralName.jbClearGeneralName.image")));
		jbClearGeneralName = new JButton(clearIcon);
		jbClearGeneralName.setToolTipText(res.getString("JGeneralName.jbClearGeneralName.tooltip"));
		jbClearGeneralName.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JGeneralName.this);
					clearGeneralName();
				} finally {
					CursorUtil.setCursorFree(JGeneralName.this);
				}
			}
		});

		GridBagConstraints gbc_jbClearGeneralName = new GridBagConstraints();
		gbc_jbClearGeneralName.gridwidth = 1;
		gbc_jbClearGeneralName.gridheight = 1;
		gbc_jbClearGeneralName.gridx = 2;
		gbc_jbClearGeneralName.gridy = 0;
		gbc_jbClearGeneralName.insets = new Insets(0, 0, 0, 0);

		setLayout(new GridBagLayout());
		add(jtfGeneralName, gbc_jtfGeneralName);
		add(jbEditGeneralName, gbc_jbEditGeneralName);
		add(jbClearGeneralName, gbc_jbClearGeneralName);

		populate();
	}

	/**
	 * Get general name.
	 *
	 * @return General name, or null if none chosen
	 */
	public GeneralName getGeneralName() {
		return generalName;
	}

	/**
	 * Set general name.
	 *
	 * @param generalName
	 *            General name
	 */
	public void setGeneralName(GeneralName generalName) {
		this.generalName = generalName;
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
		jbEditGeneralName.setEnabled(enabled);
		jbClearGeneralName.setEnabled(enabled);
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
		jtfGeneralName.setToolTipText(toolTipText);
	}

	private void populate() {
		if (generalName != null) {
			jtfGeneralName.setText(GeneralNameUtil.safeToString(generalName, false));
			jbClearGeneralName.setEnabled(true);
		} else {
			jtfGeneralName.setText("");
			jbClearGeneralName.setEnabled(false);
		}

		jtfGeneralName.setCaretPosition(0);
	}

	private void editGeneralName() {
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

		setGeneralName(newGeneralName);
	}

	private void clearGeneralName() {
		setGeneralName(null);
	}
}
