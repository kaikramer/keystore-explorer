/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2016 Kai Kramer
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

import static net.sf.keystore_explorer.crypto.keystore.KeyStoreType.SC_HSM;

import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.PasswordCallbackHandler;
import net.sf.keystore_explorer.gui.error.DError;

/**
 * Action to open the SmartCard-HSM KeyStore.
 *
 */
public class OpenSmartCardHSMAction extends OpenAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public OpenSmartCardHSMAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(
				ACCELERATOR_KEY,
				KeyStroke.getKeyStroke(res.getString("OpenSmartCardHSMAction.accelerator").charAt(0), Toolkit
						.getDefaultToolkit().getMenuShortcutKeyMask() + InputEvent.SHIFT_MASK));
		putValue(LONG_DESCRIPTION, res.getString("OpenSmartCardHSMAction.statusbar"));
		putValue(NAME, res.getString("OpenSmartCardHSMAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("OpenSmartCardHSMAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("OpenSmartCardHSMAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {

		try {
			Class<?> clazz = Class.forName("de.cardcontact.smartcardhsmprovider.SmartCardHSMProvider");
			Provider scHSMProvider = (Provider)clazz.newInstance();

			KeyStore keyStore = KeyStore.getInstance(SC_HSM.jce(), scHSMProvider);

			keyStore.load(null, null);

			kseFrame.addKeyStore(keyStore, scHSMProvider.getName(), null, scHSMProvider);

		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
