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
import java.io.File;
import java.io.FileNotFoundException;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to save the active KeyStore.
 *
 */
public class SaveAction extends SaveAsAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public SaveAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("SaveAction.accelerator").charAt(0), Toolkit
				.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("SaveAction.statusbar"));
		putValue(NAME, res.getString("SaveAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SaveAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("SaveAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		saveKeyStore(kseFrame.getActiveKeyStoreHistory());
	}

	/**
	 * Save the supplied KeyStore back to the file it was originally opened
	 * from.
	 *
	 * @param history
	 *            KeyStore history
	 * @return True if the KeyStore is saved to disk, false otherwise
	 */
	protected boolean saveKeyStore(KeyStoreHistory history) {
		File saveFile = null;

		try {
			KeyStoreState currentState = history.getCurrentState();

			kseFrame.focusOnKeyStore(currentState.getKeyStore());

			saveFile = history.getFile();

			if (saveFile == null) {
				return saveKeyStoreAs(history);
			}

			Password password = currentState.getPassword();

			if (password == null) {
				SetPasswordAction setPasswordAction = new SetPasswordAction(kseFrame);

				if (setPasswordAction.setKeyStorePassword()) {
					currentState = history.getCurrentState();
					password = currentState.getPassword();
				} else {
					return false;
				}
			}

			KeyStoreUtil.save(currentState.getKeyStore(), saveFile, password);

			currentState.setPassword(password);
			currentState.setAsSavedState();

			kseFrame.updateControls(false);

			return true;
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("SaveAction.NoWriteFile.message"), saveFile),
					res.getString("SaveAction.SaveKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
			return false;
		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return false;
		}
	}
}
