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
package org.kse.gui.actions;

import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.net.URI;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.KSE;
import org.kse.gui.KseFrame;
import org.kse.utilities.net.URLs;

/**
 * Action to show help.
 *
 */
public class HelpAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	private String websiteAddress;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public HelpAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0));
		putValue(LONG_DESCRIPTION, res.getString("HelpAction.statusbar"));
		putValue(NAME, res.getString("HelpAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("HelpAction.tooltip"));
		putValue(SMALL_ICON,new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource("images/help.png"))));

		websiteAddress = URLs.KSE_USER_MANUAL + KSE.getUserManualVersion() + "/";
	}


	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			Desktop.getDesktop().browse(URI.create(websiteAddress));
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("WebsiteAction.NoLaunchBrowser.message"), websiteAddress),
					KSE.getApplicationName(), JOptionPane.INFORMATION_MESSAGE);
		}
	}

}
