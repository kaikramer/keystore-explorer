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
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to set the active KeyStore's password.
 *
 */
public class SetPasswordAction extends KeyStoreExplorerAction implements HistoryAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public SetPasswordAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("SetPasswordAction.accelerator").charAt(0),
				Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("SetPasswordAction.statusbar"));
		putValue(NAME, res.getString("SetPasswordAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SetPasswordAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("SetPasswordAction.image")))));
	}

	@Override
	public String getHistoryDescription() {
		return res.getString("SetPasswordAction.History.text");
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			if (setKeyStorePassword()) {
				JOptionPane.showMessageDialog(frame,
						res.getString("SetPasswordAction.SetKeyStorePasswordSuccessful.message"),
						res.getString("SetPasswordAction.SetKeyStorePassword.Title"), JOptionPane.INFORMATION_MESSAGE);
			}
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	/**
	 * Set the active KeyStore's password.
	 *
	 * @return True if successful
	 * @throws CryptoException
	 *             If problem occurred
	 */
	protected boolean setKeyStorePassword() throws CryptoException {
		KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

		KeyStoreState currentState = history.getCurrentState();
		KeyStoreState newState = currentState.createBasisForNextState(this);

		Password password = getNewKeyStorePassword();

		if (password == null) {
			return false;
		}

		newState.setPassword(password);

		currentState.append(newState);

		kseFrame.updateControls(true);

		return true;
	}
}
