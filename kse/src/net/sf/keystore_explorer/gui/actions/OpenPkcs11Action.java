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
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.Provider;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.PKCS11;

import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DOpenPkcs11KeyStore;
import net.sf.keystore_explorer.gui.dialogs.PasswordCallbackHandler;
import net.sf.keystore_explorer.gui.error.DError;

/**
 * Action to open the PKCS11 KeyStore. If it does not exist provide the
 * user with the option of creating it.
 *
 */
public class OpenPkcs11Action extends OpenAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public OpenPkcs11Action(KseFrame kseFrame) {
		super(kseFrame);

		putValue(
				ACCELERATOR_KEY,
				KeyStroke.getKeyStroke(res.getString("OpenPkcs11Action.accelerator").charAt(0), Toolkit
						.getDefaultToolkit().getMenuShortcutKeyMask() + InputEvent.SHIFT_MASK));
		putValue(LONG_DESCRIPTION, res.getString("OpenPkcs11Action.statusbar"));
		putValue(NAME, res.getString("OpenPkcs11Action.text"));
		putValue(SHORT_DESCRIPTION, res.getString("OpenPkcs11Action.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("OpenPkcs11Action.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {

		try {
			DOpenPkcs11KeyStore dOpenPkcs11KeyStore = new DOpenPkcs11KeyStore(frame);
			dOpenPkcs11KeyStore.setLocationRelativeTo(frame);
			dOpenPkcs11KeyStore.setVisible(true);

			Provider selectedProvider = dOpenPkcs11KeyStore.getSelectedProvider();
			if (selectedProvider == null) {
				return;
			}

			KeyStore keyStore = KeyStore.getInstance(PKCS11.jce(), selectedProvider);

			// register password handler
			AuthProvider authProvider = (AuthProvider) selectedProvider;
			authProvider.setCallbackHandler(new PasswordCallbackHandler(frame));

			keyStore.load(null, null);

			kseFrame.addKeyStore(keyStore, selectedProvider.getName(), null, selectedProvider);

		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
