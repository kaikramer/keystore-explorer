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
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.gui.KseFrame;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to close the active KeyStore.
 *
 */
public class CloseAction extends SaveAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public CloseAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("CloseAction.accelerator").charAt(0), Toolkit
				.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("CloseAction.statusbar"));
		putValue(NAME, res.getString("CloseAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("CloseAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("CloseAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		closeActiveKeyStore();
	}

	/**
	 * Close the active KeyStore. Allow the user to save it if there are unsaved
	 * changes.
	 *
	 * @return True if the KeyStore is closed, false otherwise
	 */
	public boolean closeActiveKeyStore() {
		return closeKeyStore(kseFrame.getActiveKeyStoreHistory());
	}

	/**
	 * Close the supplied KeyStore. Allow the user to save it if there are
	 * unsaved changes.
	 *
	 * @param history
	 *            KeyStore history
	 * @return True if the KeyStore is closed, false otherwise
	 */
	public boolean closeKeyStore(KeyStoreHistory history) {
		KeyStoreState currentState = history.getCurrentState();

		if (needSave(currentState)) {
			kseFrame.focusOnKeyStore(currentState.getKeyStore());

			int wantSave = wantSave(history);

			if (wantSave == JOptionPane.YES_OPTION) {
				boolean saved = saveKeyStore(history);

				if (!saved) {
					return false;
				}

				// Current state may have changed with the addition of a
				// KeyStore password during
				// save
				currentState = history.getCurrentState();
			} else if ((wantSave == JOptionPane.CANCEL_OPTION) || (wantSave == JOptionPane.CLOSED_OPTION)) {
				return false;
			}
		}

		kseFrame.removeKeyStore(currentState.getKeyStore());
		kseFrame.updateControls(true);

		return true;
	}

	private boolean needSave(KeyStoreState state) {
		if (state != null) {
			if (!state.isSavedState() && !state.isInitialState()) {
				return true;
			}
		}
		return false;
	}

	private int wantSave(KeyStoreHistory history) {
		String keyStoreName = history.getName();

		String message = MessageFormat.format(res.getString("CloseAction.WantSaveChanges.message"), keyStoreName);

		int selected = JOptionPane.showConfirmDialog(frame, message,
				res.getString("CloseAction.WantSaveChanges.Title"), JOptionPane.YES_NO_CANCEL_OPTION);
		return selected;
	}
}
