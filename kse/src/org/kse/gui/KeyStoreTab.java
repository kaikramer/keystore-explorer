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
package org.kse.gui;

import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import org.kse.gui.actions.CloseAction;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * KeyStore tab. Displays a KeyStore's title and allows it to be closed using a
 * close icon.
 *
 */
public class KeyStoreTab extends JPanel {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");
	private JLabel jlTitle;
	private JButton jbClose;
	private KseFrame kseFrame;
	private KeyStoreHistory history;

	/**
	 * Construct KeyStore tab.
	 *
	 * @param title
	 *            Tab title
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 * @param history
	 *            KeyStore contained in tab
	 */
	public KeyStoreTab(String title, KseFrame kseFrame, KeyStoreHistory history) {
		this.kseFrame = kseFrame;
		this.history = history;

		initComponents(title);
	}

	private void initComponents(String title) {
		jlTitle = new JLabel(title);
		jlTitle.setBorder(new EmptyBorder(0, 0, 0, 5));

		jbClose = new JButton();
		jbClose.setToolTipText(res.getString("KeyStoreTab.jbClose.tooltip"));

		final ImageIcon icon = new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("KeyStoreTab.CloseTab.image"))));

		final ImageIcon rollOverIcon = new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("KeyStoreTab.CloseTabRollOver.image"))));

		jbClose.setSize(icon.getImage().getWidth(null), icon.getImage().getHeight(null));
		jbClose.setIcon(icon);

		// Do our own roll-over using mouse and action event handlers
		jbClose.setRolloverEnabled(false);

		// Remove un-needed button functionality and decoration
		jbClose.setMargin(new Insets(0, 0, 0, 0));
		jbClose.setBorderPainted(false);
		jbClose.setBorder(null);
		jbClose.setText(null);
		jbClose.setContentAreaFilled(false);
		jbClose.setFocusPainted(false);
		jbClose.setFocusable(false);

		jbClose.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseEntered(MouseEvent evt) {
				jbClose.setIcon(rollOverIcon);
			}

			@Override
			public void mouseExited(MouseEvent evt) {
				jbClose.setIcon(icon);
			}
		});

		jbClose.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				jbClose.setIcon(icon);
				CloseAction closeAction = new CloseAction(kseFrame);
				closeAction.closeKeyStore(history);
			}
		});

		setOpaque(false);
		setLayout(new FlowLayout(FlowLayout.CENTER, 0, 0));

		add(jlTitle);
		add(jbClose);
	}

	/**
	 * Update the tab's title.
	 *
	 * @param title
	 *            New tab title
	 */
	public void updateTitle(String title) {
		jlTitle.setText(title);
	}
}
