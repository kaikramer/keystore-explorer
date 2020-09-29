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

import java.awt.Toolkit;
import java.security.KeyStore;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to delete multiple selected entries.
 *
 */
public class DeleteMultipleEntriesAction extends KeyStoreExplorerAction implements HistoryAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public DeleteMultipleEntriesAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("DeleteMultipleEntriesAction.statusbar"));
		putValue(NAME, res.getString("DeleteMultipleEntriesAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("DeleteMultipleEntriesAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource("images/delete.png"))));
	}

	@Override
	public String getHistoryDescription() {
		return (String) getValue(NAME);
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		deleteSelectedEntries();
	}

	/**
	 * Let the user delete the selected KeyStore entry.
	 */
	public void deleteSelectedEntries() {
		String[] aliases = kseFrame.getSelectedEntryAliases();
		if (aliases.length == 0) {
			return;
		}

		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

			KeyStoreState currentState = history.getCurrentState();
			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();

			int selected = JOptionPane.showConfirmDialog(frame, res.getString("DeleteMultipleEntriesAction.ConfirmDelete.message"),
					res.getString("DeleteMultipleEntriesAction.DeleteEntry.Title"), JOptionPane.YES_NO_OPTION);

			if (selected != JOptionPane.YES_OPTION) {
				return;
			}

			for (String alias : aliases) {
				keyStore.deleteEntry(alias);
				newState.removeEntryPassword(alias);
			}

			currentState.append(newState);

			kseFrame.updateControls(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
