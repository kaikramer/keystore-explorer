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
import java.awt.event.InputEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.history.KeyStoreState;

/**
 * Action to save all KeyStores.
 *
 */
public class SaveAllAction extends SaveAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public SaveAllAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(
				ACCELERATOR_KEY,
				KeyStroke.getKeyStroke(res.getString("SaveAllAction.accelerator").charAt(0), Toolkit
						.getDefaultToolkit().getMenuShortcutKeyMask() + InputEvent.SHIFT_MASK));
		putValue(LONG_DESCRIPTION, res.getString("SaveAllAction.statusbar"));
		putValue(NAME, res.getString("SaveAllAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SaveAllAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("SaveAllAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			KeyStoreHistory[] histories = kseFrame.getKeyStoreHistories();

			for (int i = 0; i < histories.length; i++) {
				KeyStoreHistory history = histories[i];
				KeyStoreState currentState = history.getCurrentState();

				// Does KeyStore require saving and has file been saved before?
				if (!currentState.isSavedState()) {
					if (!saveKeyStore(history)) {
						break;
					}
				}
			}
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
