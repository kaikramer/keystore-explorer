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
import java.awt.event.InputEvent;
import java.security.KeyStore;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.MsCapiStoreType;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;

/**
 * Action to open the PKCS11 KeyStore. If it does not exist provide the
 * user with the option of creating it.
 *
 */
public class OpenMsCapiAction  extends OpenAction {

	private static final long serialVersionUID = -9068103518220241052L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public OpenMsCapiAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(
				ACCELERATOR_KEY,
				KeyStroke.getKeyStroke(res.getString("OpenMsCapiAction.accelerator").charAt(0), Toolkit
						.getDefaultToolkit().getMenuShortcutKeyMask() + InputEvent.SHIFT_MASK));
		putValue(LONG_DESCRIPTION, res.getString("OpenMsCapiAction.statusbar"));
		putValue(NAME, res.getString("OpenMsCapiAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("OpenMsCapiAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("OpenMsCapiAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {

		try {

			KeyStore openedKeyStore = KeyStoreUtil.loadMsCapiStore(MsCapiStoreType.PERSONAL);

			// https://bugs.openjdk.java.net/browse/JDK-6407454
			// "The SunMSCAPI provider doesn't support access to the RSA keys that it generates.
			// Users of the keytool utility must omit the SunMSCAPI provider from the -provider option and
			// applications must not specify the SunMSCAPI provider."

			kseFrame.addKeyStore(openedKeyStore, res.getString("OpenMsCapiAction.TabTitle"), null, null);

		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

}
