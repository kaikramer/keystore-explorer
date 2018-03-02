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
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.buffer.Buffer;
import org.kse.utilities.buffer.BufferEntry;
import org.kse.utilities.buffer.KeyBufferEntry;
import org.kse.utilities.buffer.KeyPairBufferEntry;
import org.kse.utilities.buffer.TrustedCertificateBufferEntry;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to copy a KeyStore entry.
 *
 */
public class CopyAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public CopyAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("CopyAction.accelerator").charAt(0), Toolkit
				.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("CopyAction.statusbar"));
		putValue(NAME, res.getString("CopyAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("CopyAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("CopyAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		BufferEntry bufferEntry = bufferSelectedEntry();

		if (bufferEntry != null) {
			Buffer.populate(bufferEntry);
			kseFrame.updateControls(false);
		}
	}

	private BufferEntry bufferSelectedEntry() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			String alias = kseFrame.getSelectedEntryAlias();

			if (alias == null) {
				return null;
			}

			BufferEntry bufferEntry = null;

			KeyStore keyStore = currentState.getKeyStore();

			if (KeyStoreUtil.isKeyEntry(alias, keyStore)) {
				Password password = getEntryPassword(alias, currentState);

				if (password == null) {
					return null;
				}

				Key key = keyStore.getKey(alias, password.toCharArray());

				if (key instanceof PrivateKey) {
					JOptionPane.showMessageDialog(frame,
							res.getString("CopyAction.NoCopyKeyEntryWithPrivateKey.message"),
							res.getString("CopyAction.Copy.Title"), JOptionPane.WARNING_MESSAGE);

					return null;
				}

				bufferEntry = new KeyBufferEntry(alias, false, key, password);
			} else if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
				Certificate certificate = keyStore.getCertificate(alias);

				bufferEntry = new TrustedCertificateBufferEntry(alias, false, certificate);
			} else if (KeyStoreUtil.isKeyPairEntry(alias, keyStore)) {
				Password password = getEntryPassword(alias, currentState);

				if (password == null) {
					return null;
				}

				PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
				Certificate[] certificateChain = keyStore.getCertificateChain(alias);

				bufferEntry = new KeyPairBufferEntry(alias, false, privateKey, password, certificateChain);
			}

			return bufferEntry;
		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return null;
		}
	}
}
