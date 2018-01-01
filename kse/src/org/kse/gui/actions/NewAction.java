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
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DNewKeyStoreType;
import org.kse.gui.error.DError;

/**
 * Action to create a new KeyStore.
 *
 */
public class NewAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;
	private static int untitledCount = 0;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public NewAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("NewAction.accelerator").charAt(0), Toolkit
				.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("NewAction.statusbar"));
		putValue(NAME, res.getString("NewAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("NewAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("NewAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			DNewKeyStoreType dNewKeyStoreType = new DNewKeyStoreType(frame);
			dNewKeyStoreType.setLocationRelativeTo(frame);
			dNewKeyStoreType.setVisible(true);

			KeyStoreType keyStoreType = dNewKeyStoreType.getKeyStoreType();

			if (keyStoreType == null) {
				return;
			}

			KeyStore newKeyStore = KeyStoreUtil.create(keyStoreType);

			untitledCount++;
			String untitled = MessageFormat.format(res.getString("NewAction.Untitled"), untitledCount);

			kseFrame.addKeyStore(newKeyStore, untitled, null, null);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
