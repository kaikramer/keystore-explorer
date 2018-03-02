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
import java.security.KeyStore;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to delete the selected trusted certificate.
 *
 */
public class DeleteTrustedCertificateAction extends KeyStoreExplorerAction implements HistoryAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public DeleteTrustedCertificateAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("DeleteTrustedCertificateAction.statusbar"));
		putValue(NAME, res.getString("DeleteTrustedCertificateAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("DeleteTrustedCertificateAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("DeleteTrustedCertificateAction.image")))));
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
		deleteSelectedEntry();
	}

	/**
	 * Let the user delete the selected KeyStore entry.
	 */
	public void deleteSelectedEntry() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

			KeyStoreState currentState = history.getCurrentState();
			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();
			String alias = kseFrame.getSelectedEntryAlias();

			String message = MessageFormat.format(
					res.getString("DeleteTrustedCertificateAction.ConfirmDelete.message"), alias);
			int selected = JOptionPane.showConfirmDialog(frame, message,
					res.getString("DeleteTrustedCertificateAction.DeleteEntry.Title"), JOptionPane.YES_NO_OPTION);

			if (selected != JOptionPane.YES_OPTION) {
				return;
			}

			keyStore.deleteEntry(alias);

			currentState.append(newState);

			kseFrame.updateControls(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
