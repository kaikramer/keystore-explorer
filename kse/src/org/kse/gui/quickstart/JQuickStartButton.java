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
package org.kse.gui.quickstart;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.Action;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 * Quick Start button. Undecorated image button with attached descriptive text
 * that each react to mouse roll-overs.
 *
 */
public class JQuickStartButton extends JPanel {
	private static final long serialVersionUID = 1L;
	private JButton jbWelcome;
	private JLabel jlWelcome;

	/**
	 * Initialise component and its subcomponents.
	 *
	 * @param action
	 *            Button action
	 * @param test
	 *            Button text
	 * @param icon
	 *            Button icon
	 * @param rollOverIcon
	 *            Button rollover icon
	 * @param foreground
	 *            Foreground color for text
	 * @param rollOverColor
	 *            Rollover color for text
	 */
	public JQuickStartButton(Action action, String test, final ImageIcon icon, final ImageIcon rollOverIcon,
			final Color foreground, final Color rollOverColor) {
		jlWelcome = new JLabel(test);
		jlWelcome.setForeground(foreground);

		jbWelcome = new JButton();
		jbWelcome.setAction(action);

		jbWelcome.setSize(icon.getImage().getWidth(null), icon.getImage().getHeight(null));
		jbWelcome.setIcon(icon);

		// We'll do our own roll-over using mouse and action event handlers
		jbWelcome.setRolloverEnabled(false);

		// Removed un-needed button functionality and decoration
		jbWelcome.setMargin(new Insets(0, 0, 0, 0));
		jbWelcome.setIconTextGap(0);
		jbWelcome.setBorderPainted(false);
		jbWelcome.setBorder(null);
		jbWelcome.setText(null);
		jbWelcome.setToolTipText(null);
		jbWelcome.setContentAreaFilled(false);
		jbWelcome.setFocusPainted(false);
		jbWelcome.setFocusable(false);

		// Add roll-over supporting events

		jbWelcome.addMouseListener(new MouseAdapter() {
			// Mouse entered - use roll-over color on text and image on button
			@Override
			public void mouseEntered(MouseEvent evt) {
				jlWelcome.setForeground(rollOverColor);
				jbWelcome.setIcon(rollOverIcon);
			}

			// Mouse exited - remove roll-over color on text and image on button
			@Override
			public void mouseExited(MouseEvent evt) {
				jlWelcome.setForeground(foreground);
				jbWelcome.setIcon(icon);
			}
		});

		jbWelcome.addActionListener(new ActionListener() {
			// Button activate - remove roll-over color on text and image on
			// button
			@Override
			public void actionPerformed(ActionEvent evt) {
				jlWelcome.setForeground(foreground);
				jbWelcome.setIcon(icon);
			}
		});

		GridBagConstraints gbc_jlWelcome = new GridBagConstraints();
		gbc_jlWelcome.gridheight = 1;
		gbc_jlWelcome.gridwidth = 1;
		gbc_jlWelcome.gridx = 0;
		gbc_jlWelcome.gridy = 1;
		gbc_jlWelcome.insets = new Insets(3, 0, 0, 0);

		GridBagConstraints gbc_jbWelcome = new GridBagConstraints();
		gbc_jbWelcome.gridheight = 1;
		gbc_jbWelcome.gridwidth = 1;
		gbc_jbWelcome.gridx = 0;
		gbc_jbWelcome.gridy = 0;
		gbc_jbWelcome.insets = new Insets(0, 0, 3, 0);

		setLayout(new GridBagLayout());

		add(jbWelcome, gbc_jbWelcome);
		add(jlWelcome, gbc_jlWelcome);
	}
}
