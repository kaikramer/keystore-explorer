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
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.MessageFormat;

import javax.crypto.SecretKey;
import javax.swing.ImageIcon;

import net.sf.keystore_explorer.crypto.Password;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DViewPrivateKey;
import net.sf.keystore_explorer.gui.dialogs.DViewPublicKey;
import net.sf.keystore_explorer.gui.dialogs.DViewSecretKey;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.history.KeyStoreState;

/**
 * Action to display details for the selected key entry.
 *
 */
public class KeyDetailsAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public KeyDetailsAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("KeyDetailsAction.statusbar"));
		putValue(NAME, res.getString("KeyDetailsAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("KeyDetailsAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("KeyDetailsAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		showKeySelectedEntry();
	}

	/**
	 * Show the key details of the selected KeyStore entry.
	 */
	public void showKeySelectedEntry() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();
			String alias = kseFrame.getSelectedEntryAlias();

			Password password = getEntryPassword(alias, currentState);

			if (password == null) {
				return;
			}

			KeyStore keyStore = currentState.getKeyStore();

			Key key = keyStore.getKey(alias, password.toCharArray());

			if (key instanceof SecretKey) {
				SecretKey secretKey = (SecretKey) key;

				DViewSecretKey dViewSecretKey = new DViewSecretKey(frame, MessageFormat.format(
						res.getString("KeyDetailsAction.SecretKeyDetailsEntry.Title"), alias), secretKey);
				dViewSecretKey.setLocationRelativeTo(frame);
				dViewSecretKey.setVisible(true);
			} else if (key instanceof PrivateKey) {
				PrivateKey privateKey = (PrivateKey) key;

				DViewPrivateKey dViewPrivateKey = new DViewPrivateKey(frame, MessageFormat.format(
						res.getString("KeyDetailsAction.PrivateKeyDetailsEntry.Title"), alias), privateKey,
						history.getExplicitProvider());
				dViewPrivateKey.setLocationRelativeTo(frame);
				dViewPrivateKey.setVisible(true);
			} else if (key instanceof PublicKey) {
				PublicKey publicKey = (PublicKey) key;

				DViewPublicKey dViewPublicKey = new DViewPublicKey(frame, MessageFormat.format(
						res.getString("KeyDetailsAction.PublicKeyDetailsEntry.Title"), alias), publicKey);
				dViewPublicKey.setLocationRelativeTo(frame);
				dViewPublicKey.setVisible(true);
			}
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
