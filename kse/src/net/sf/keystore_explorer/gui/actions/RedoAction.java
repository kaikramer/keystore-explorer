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
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.history.KeyStoreState;

/**
 * Action to redo an action.
 *
 */
public class RedoAction extends KeyStoreExplorerAction {
	private String defaultName;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public RedoAction(KseFrame kseFrame) {
		super(kseFrame);

		defaultName = res.getString("RedoAction.text");

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("RedoAction.accelerator").charAt(0), Toolkit
				.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("RedoAction.statusbar"));
		putValue(NAME, defaultName);
		putValue(SHORT_DESCRIPTION, res.getString("RedoAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("RedoAction.image")))));
	}

	/**
	 * Enable or disable the action.
	 *
	 * @param enabled
	 *            True to enable, false to disable it
	 */
	@Override
	public void setEnabled(boolean enabled) {
		super.setEnabled(enabled);

		if (enabled) {
			KeyStoreState currentState = kseFrame.getActiveKeyStoreHistory().getCurrentState();
			KeyStoreState nextState = currentState.nextState();
			putValue(NAME,
					MessageFormat.format(res.getString("RedoAction.dynamic.text"), nextState.getActionDescription()));
		} else {
			putValue(NAME, defaultName);
		}
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

			history.getCurrentState().setNextStateAsCurrentState();

			kseFrame.updateControls(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
