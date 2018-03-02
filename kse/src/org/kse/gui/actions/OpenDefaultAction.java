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
import java.io.File;
import java.security.KeyStore;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DNewKeyStoreType;
import org.kse.gui.error.DError;

/**
 * Action to open the default KeyStore. If it does not exist provide the user
 * with the option of creating it.
 *
 */
public class OpenDefaultAction extends OpenAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public OpenDefaultAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(
				ACCELERATOR_KEY,
				KeyStroke.getKeyStroke(res.getString("OpenDefaultAction.accelerator").charAt(0), Toolkit
						.getDefaultToolkit().getMenuShortcutKeyMask() + InputEvent.SHIFT_MASK));
		putValue(LONG_DESCRIPTION, res.getString("OpenDefaultAction.statusbar"));
		putValue(NAME, res.getString("OpenDefaultAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("OpenDefaultAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("OpenDefaultAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		File defaultKeyStoreFile = new File(System.getProperty("user.home"), ".keystore");

		if (defaultKeyStoreFile.isFile()) {
			openKeyStore(defaultKeyStoreFile);
			return;
		}

		int selected = JOptionPane.showConfirmDialog(frame,
				res.getString("OpenDefaultAction.NoDefaultKeyStoreCreate.message"),
				res.getString("OpenDefaultAction.OpenDefaultKeyStore.Title"), JOptionPane.YES_NO_OPTION);

		if (selected != JOptionPane.YES_OPTION) {
			return;
		}

		try {
			DNewKeyStoreType dNewKeyStoreType = new DNewKeyStoreType(frame);
			dNewKeyStoreType.setLocationRelativeTo(frame);
			dNewKeyStoreType.setVisible(true);

			KeyStoreType keyStoreType = dNewKeyStoreType.getKeyStoreType();

			if (keyStoreType == null) {
				return;
			}

			Password password = getNewKeyStorePassword();

			if (password == null) {
				return;
			}

			KeyStore defaultKeyStore = KeyStoreUtil.create(keyStoreType);
			KeyStoreUtil.save(defaultKeyStore, defaultKeyStoreFile, password);

			kseFrame.addKeyStore(defaultKeyStore, defaultKeyStoreFile, password);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
