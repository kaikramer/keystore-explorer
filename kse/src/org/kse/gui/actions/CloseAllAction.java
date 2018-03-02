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
package org.kse.gui.actions;

import java.awt.Toolkit;
import java.awt.event.InputEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.gui.KseFrame;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to close all KeyStores.
 *
 */
public class CloseAllAction extends CloseAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public CloseAllAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(
				ACCELERATOR_KEY,
				KeyStroke.getKeyStroke(res.getString("CloseAllAction.accelerator").charAt(0), Toolkit
						.getDefaultToolkit().getMenuShortcutKeyMask() + InputEvent.SHIFT_MASK));
		putValue(LONG_DESCRIPTION, res.getString("CloseAllAction.statusbar"));
		putValue(NAME, res.getString("CloseAllAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("CloseAllAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("CloseAllAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		closeAllKeyStores();
	}

	/**
	 * Close all keyStores.
	 *
	 * @return True if all KeyStores closed, false otherwise
	 */
	protected boolean closeAllKeyStores() {
		KeyStoreHistory[] histories = kseFrame.getKeyStoreHistories();

		while (histories.length > 0) {
			if (!closeKeyStore(histories[0])) {
				break;
			}

			histories = kseFrame.getKeyStoreHistories();
		}

		return histories.length == 0;

	}
}
