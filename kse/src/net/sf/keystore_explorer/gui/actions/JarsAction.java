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
package net.sf.keystore_explorer.gui.actions;

import java.awt.Toolkit;

import javax.swing.ImageIcon;

import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.gui.jar.DJarInfo;

/**
 * Action to display the JARs information dialog.
 *
 */
public class JarsAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public JarsAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("JarsAction.statusbar"));
		putValue(NAME, res.getString("JarsAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("JarsAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("JarsAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			DJarInfo dJarInfo = new DJarInfo(frame);
			dJarInfo.setLocationRelativeTo(frame);
			dJarInfo.setVisible(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
