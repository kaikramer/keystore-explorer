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

import org.bouncycastle.asn1.x509.UserNotice;
import org.kse.crypto.x509.PolicyInformationUtil;
import org.kse.gui.CursorUtil;

/**
 * Component to edit a user notice.
 *
 */
public class JUserNotice extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/policyinformation/resources");

	private JTextField jtfUserNotice;
	private JButton jbEditUserNotice;
	private JButton jbClearUserNotice;

	private String title;
	private UserNotice userNotice;

	/**
	 * Construct a JUserNotice.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JUserNotice(String title) {
		this.title = title;
		initComponents();
	}

	private void initComponents() {
		jtfUserNotice = new JTextField(20);
		jtfUserNotice.setEditable(false);

		GridBagConstraints gbc_jtfUserNotice = new GridBagConstraints();
		gbc_jtfUserNotice.gridwidth = 1;
		gbc_jtfUserNotice.gridheight = 1;
		gbc_jtfUserNotice.gridx = 0;
		gbc_jtfUserNotice.gridy = 0;
		gbc_jtfUserNotice.insets = new Insets(0, 0, 0, 5);

		ImageIcon editIcon = new ImageIcon(getClass().getResource(res.getString("JUserNotice.jbEditUserNotice.image")));
		jbEditUserNotice = new JButton(editIcon);
		jbEditUserNotice.setToolTipText(res.getString("JUserNotice.jbEditUserNotice.tooltip"));
		jbEditUserNotice.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JUserNotice.this);
					editUserNotice();
				} finally {
					CursorUtil.setCursorFree(JUserNotice.this);
				}
			}
		});

		GridBagConstraints gbc_jbEditUserNotice = new GridBagConstraints();
		gbc_jbEditUserNotice.gridwidth = 1;
		gbc_jbEditUserNotice.gridheight = 1;
		gbc_jbEditUserNotice.gridx = 1;
		gbc_jbEditUserNotice.gridy = 0;
		gbc_jbEditUserNotice.insets = new Insets(0, 0, 0, 5);

		ImageIcon clearIcon = new ImageIcon(getClass()
				.getResource(res.getString("JUserNotice.jbClearUserNotice.image")));
		jbClearUserNotice = new JButton(clearIcon);
		jbClearUserNotice.setToolTipText(res.getString("JUserNotice.jbClearUserNotice.tooltip"));
		jbClearUserNotice.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JUserNotice.this);
					clearUserNotice();
				} finally {
					CursorUtil.setCursorFree(JUserNotice.this);
				}
			}
		});

		GridBagConstraints gbc_jbClearUserNotice = new GridBagConstraints();
		gbc_jbClearUserNotice.gridwidth = 1;
		gbc_jbClearUserNotice.gridheight = 1;
		gbc_jbClearUserNotice.gridx = 2;
		gbc_jbClearUserNotice.gridy = 0;
		gbc_jbClearUserNotice.insets = new Insets(0, 0, 0, 0);

		setLayout(new GridBagLayout());
		add(jtfUserNotice, gbc_jtfUserNotice);
		add(jbEditUserNotice, gbc_jbEditUserNotice);
		add(jbClearUserNotice, gbc_jbClearUserNotice);

		populate();
	}

	/**
	 * Get user notice.
	 *
	 * @return User notice, or null if none chosen
	 */
	public UserNotice getUserNotice() {
		return userNotice;
	}

	/**
	 * Set user notice.
	 *
	 * @param userNotice
	 *            User notice
	 */
	public void setUserNotice(UserNotice userNotice) {
		this.userNotice = userNotice;
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
		jbEditUserNotice.setEnabled(enabled);
		jbClearUserNotice.setEnabled(enabled);
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
		jtfUserNotice.setToolTipText(toolTipText);
	}

	private void populate() {
		if (userNotice != null) {
			jtfUserNotice.setText(PolicyInformationUtil.toString(userNotice));
			jbClearUserNotice.setEnabled(true);
		} else {
			jtfUserNotice.setText("");
			jbClearUserNotice.setEnabled(false);
		}

		jtfUserNotice.setCaretPosition(0);
	}

	private void editUserNotice() {
		Container container = getTopLevelAncestor();

		DUserNoticeChooser dUserNoticeChooser = null;

		if (container instanceof JDialog) {
			dUserNoticeChooser = new DUserNoticeChooser((JDialog) container, title, userNotice);
			dUserNoticeChooser.setLocationRelativeTo(container);
			dUserNoticeChooser.setVisible(true);
		} else if (container instanceof JFrame) {
			dUserNoticeChooser = new DUserNoticeChooser((JFrame) container, title, userNotice);
			dUserNoticeChooser.setLocationRelativeTo(container);
			dUserNoticeChooser.setVisible(true);
		}

		UserNotice newUserNotice = dUserNoticeChooser.getUserNotice();

		if (newUserNotice == null) {
			return;
		}

		setUserNotice(newUserNotice);
	}

	private void clearUserNotice() {
		setUserNotice(null);
	}
}
