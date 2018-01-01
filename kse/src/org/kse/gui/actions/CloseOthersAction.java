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

import javax.swing.ImageIcon;

import org.kse.gui.KseFrame;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to close other KeyStores.
 *
 */
public class CloseOthersAction extends CloseAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public CloseOthersAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, null);
		putValue(LONG_DESCRIPTION, res.getString("CloseOthersAction.statusbar"));
		putValue(NAME, res.getString("CloseOthersAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("CloseOthersAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("CloseOthersAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		// Get the currently active KeyStore - the one to keep open
		KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

		/*
		 * Keep closing the KeyStores while there are more open KeyStores than
		 * the active one and closing the last one was successful
		 */
		KeyStoreHistory[] histories = kseFrame.getKeyStoreHistories();

		while (histories.length > 1) {
			// Active KeyStore's index may have changed since last loop
			// iteration
			int activeIndex = kseFrame.findKeyStoreIndex(history.getCurrentState().getKeyStore());

			// Get index of next keyStore to close
			int nextCloseIndex = (activeIndex == 0) ? 1 : 0;

			if (!closeKeyStore(histories[nextCloseIndex])) {
				break;
			}

			histories = kseFrame.getKeyStoreHistories();
		}
	}
}
