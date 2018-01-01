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
package org.kse.gui.datetime;

import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Date;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.kse.gui.CursorUtil;
import org.kse.utilities.StringUtils;

/**
 * Component to edit a date/time value.
 *
 */
public class JDateTime extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/datetime/resources");

	private JTextField jtfDateTime;
	private JButton jbEditDateTime;
	private JButton jbClearDateTime;

	private String title;
	private Date date;
	private boolean showClearButton = true;

	/**
	 * Construct a JDateTime.
	 *
	 * @param title
	 *            Title of edit dialog
	 */
	public JDateTime(String title) {
		this(title, true);
	}

	/**
	 * Construct a JDateTime.
	 *
	 * @param title
	 *            Title of edit dialog
	 * @param showClearButton
	 *            if clear button is shown
	 */
	public JDateTime(String title, boolean showClearButton) {
		this.title = title;
		this.showClearButton = showClearButton;
		initComponents();
	}

	private void initComponents() {
		jtfDateTime = new JTextField(16);
		jtfDateTime.setEditable(false);

		GridBagConstraints gbc_jtfDateTime = new GridBagConstraints();
		gbc_jtfDateTime.gridwidth = 1;
		gbc_jtfDateTime.gridheight = 1;
		gbc_jtfDateTime.gridx = 0;
		gbc_jtfDateTime.gridy = 0;
		gbc_jtfDateTime.insets = new Insets(0, 0, 0, 5);

		ImageIcon editIcon = new ImageIcon(getClass().getResource(res.getString("JDateTime.jbEditDateTime.image")));
		jbEditDateTime = new JButton(editIcon);
		jbEditDateTime.setToolTipText(res.getString("JDateTime.jbEditDateTime.tooltip"));
		jbEditDateTime.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(JDateTime.this);
					editDateTime();
				} finally {
					CursorUtil.setCursorFree(JDateTime.this);
				}
			}
		});

		GridBagConstraints gbc_jbEditDateTime = new GridBagConstraints();
		gbc_jbEditDateTime.gridwidth = 1;
		gbc_jbEditDateTime.gridheight = 1;
		gbc_jbEditDateTime.gridx = 1;
		gbc_jbEditDateTime.gridy = 0;
		gbc_jbEditDateTime.insets = new Insets(0, 0, 0, 5);

		setLayout(new GridBagLayout());
		add(jtfDateTime, gbc_jtfDateTime);
		add(jbEditDateTime, gbc_jbEditDateTime);

		if (showClearButton) {
			ImageIcon clearIcon = new ImageIcon(
					getClass().getResource(res.getString("JDateTime.jbClearDateTime.image")));
			jbClearDateTime = new JButton(clearIcon);
			jbClearDateTime.setToolTipText(res.getString("JDateTime.jbClearDateTime.tooltip"));
			jbClearDateTime.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent evt) {
					try {
						CursorUtil.setCursorBusy(JDateTime.this);
						clearDateTime();
					} finally {
						CursorUtil.setCursorFree(JDateTime.this);
					}
				}
			});

			GridBagConstraints gbc_jbClearDateTime = new GridBagConstraints();
			gbc_jbClearDateTime.gridwidth = 1;
			gbc_jbClearDateTime.gridheight = 1;
			gbc_jbClearDateTime.gridx = 2;
			gbc_jbClearDateTime.gridy = 0;
			gbc_jbClearDateTime.insets = new Insets(0, 0, 0, 0);

			add(jbClearDateTime, gbc_jbClearDateTime);
		}

		populate();
	}

	/**
	 * Get date/time value.
	 *
	 * @return Date value, or null if none chosen
	 */
	public Date getDateTime() {
		return date;
	}

	/**
	 * Set date/time value.
	 *
	 * @param date
	 *            Date
	 */
	public void setDateTime(Date date) {
		this.date = date;
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
		jbEditDateTime.setEnabled(enabled);
		jbClearDateTime.setEnabled(enabled);
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
		jtfDateTime.setToolTipText(toolTipText);
	}

	private void populate() {
		if (date != null) {
			jtfDateTime.setText(StringUtils.formatDate(date));
			if (showClearButton) {
				jbClearDateTime.setEnabled(true);
			}
		} else {
			jtfDateTime.setText("");
			if (showClearButton) {
				jbClearDateTime.setEnabled(false);
			}
		}

		jtfDateTime.setCaretPosition(0);
	}

	private void editDateTime() {
		Container container = getTopLevelAncestor();

		DDateTimeChooser dDateTimeChooser = null;

		if (container instanceof JDialog) {
			dDateTimeChooser = new DDateTimeChooser((JDialog) container, title, date);
			dDateTimeChooser.setLocationRelativeTo(container);
			dDateTimeChooser.setVisible(true);
		} else if (container instanceof JFrame) {
			dDateTimeChooser = new DDateTimeChooser((JFrame) container, title, date);
			dDateTimeChooser.setLocationRelativeTo(container);
			dDateTimeChooser.setVisible(true);
		}

		Date newDate = dDateTimeChooser.getDate();

		if (newDate == null) {
			return;
		}

		setDateTime(newDate);
	}

	private void clearDateTime() {
		setDateTime(null);
	}
}
