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
import java.security.Key;
import java.security.KeyStore;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.Password;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DGetAlias;
import org.kse.gui.error.DError;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to rename the selected key entry.
 *
 */
public class RenameKeyAction extends KeyStoreExplorerAction implements HistoryAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public RenameKeyAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("RenameKeyAction.statusbar"));
		putValue(NAME, res.getString("RenameKeyAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("RenameKeyAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("RenameKeyAction.image")))));
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
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			String alias = kseFrame.getSelectedEntryAlias();

			Password password = getEntryPassword(alias, currentState);

			if (password == null) {
				return;
			}

			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();

			Key key = keyStore.getKey(alias, password.toCharArray());

			DGetAlias dGetAlias = new DGetAlias(frame, res.getString("RenameKeyAction.NewEntryAlias.Title"), alias);
			dGetAlias.setLocationRelativeTo(frame);
			dGetAlias.setVisible(true);
			String newAlias = dGetAlias.getAlias();

			if (newAlias == null) {
				return;
			}

			if (newAlias.equalsIgnoreCase(alias)) {
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("RenameKeyAction.RenameAliasIdentical.message"), alias),
						res.getString("RenameKeyAction.RenameEntry.Title"), JOptionPane.WARNING_MESSAGE);
				return;
			}

			if (keyStore.containsAlias(newAlias)) {
				String message = MessageFormat
						.format(res.getString("RenameKeyAction.OverWriteEntry.message"), newAlias);

				int selected = JOptionPane.showConfirmDialog(frame, message,
						res.getString("RenameKeyAction.RenameEntry.Title"), JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}

				keyStore.deleteEntry(newAlias);
				newState.removeEntryPassword(newAlias);
			}

			keyStore.setKeyEntry(newAlias, key, password.toCharArray(), null);
			newState.setEntryPassword(newAlias, new Password(password));

			keyStore.deleteEntry(alias);
			newState.removeEntryPassword(alias);

			currentState.append(newState);

			kseFrame.updateControls(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
