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
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.buffer.Buffer;
import org.kse.utilities.buffer.BufferEntry;
import org.kse.utilities.buffer.KeyBufferEntry;
import org.kse.utilities.buffer.KeyPairBufferEntry;
import org.kse.utilities.buffer.TrustedCertificateBufferEntry;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to paste a KeyStore entry.
 *
 */
public class PasteAction extends KeyStoreExplorerAction implements HistoryAction {

	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public PasteAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("PasteAction.accelerator").charAt(0), Toolkit
				.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("PasteAction.statusbar"));
		putValue(NAME, res.getString("PasteAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("PasteAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("PasteAction.image")))));
	}

	@Override
	public String getHistoryDescription() {
		return (String) getValue(NAME);
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		BufferEntry bufferEntry = Buffer.interrogate();

		if (bufferEntry != null) {
			boolean success = pasteEntry(bufferEntry);

			if (success) {
				kseFrame.updateControls(true);
			}
		}
	}

	private boolean pasteEntry(BufferEntry bufferEntry) {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

			KeyStoreState currentState = history.getCurrentState();
			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();

			String alias = bufferEntry.getName();

			if (keyStore.containsAlias(alias)) {
				if (bufferEntry.isCut()) {
					int selected = JOptionPane.showConfirmDialog(frame,
							MessageFormat.format(res.getString("PasteAction.PasteExistsReplace.message"), alias),
							res.getString("PasteAction.Paste.Title"), JOptionPane.YES_NO_OPTION);

					if (selected != JOptionPane.YES_OPTION) {
						return false;
					}

					keyStore.deleteEntry(alias);
					newState.removeEntryPassword(alias);
				} else {
					alias = getUniqueEntryName(alias, keyStore);
				}
			}

			if (bufferEntry instanceof KeyBufferEntry) {
				KeyStoreType keyStoreType = KeyStoreType.resolveJce(keyStore.getType());

				if (!keyStoreType.supportsKeyEntries()) {
					JOptionPane.showMessageDialog(
							frame,
							MessageFormat.format(res.getString("PasteAction.NoPasteKeyEntry.message"),
									keyStoreType.friendly()), res.getString("PasteAction.Paste.Title"),
							JOptionPane.WARNING_MESSAGE);

					return false;
				}

				KeyBufferEntry keyBufferEntry = (KeyBufferEntry) bufferEntry;

				Key key = keyBufferEntry.getKey();

				Password password = keyBufferEntry.getPassword();

				keyStore.setKeyEntry(alias, key, password.toCharArray(), null);

				newState.setEntryPassword(alias, password);
			} else if (bufferEntry instanceof KeyPairBufferEntry) {
				KeyPairBufferEntry keyPairBufferEntry = (KeyPairBufferEntry) bufferEntry;

				PrivateKey privateKey = keyPairBufferEntry.getPrivateKey();
				Password password = keyPairBufferEntry.getPassword();

				Certificate[] certificateChain = keyPairBufferEntry.getCertificateChain();

				keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), certificateChain);

				newState.setEntryPassword(alias, password);
			} else {
				TrustedCertificateBufferEntry certBufferEntry = (TrustedCertificateBufferEntry) bufferEntry;

				keyStore.setCertificateEntry(alias, certBufferEntry.getTrustedCertificate());
			}

			if (bufferEntry.isCut()) {
				Buffer.clear();
			}

			currentState.append(newState);

			kseFrame.updateControls(true);

			return true;
		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return false;
		}
	}

	private String getUniqueEntryName(String name, KeyStore keyStore) throws KeyStoreException {
		// Get unique KeyStore entry name based on the one supplied, ie *
		// "<name> (n)" where n is a
		// number.
		int i = 1;
		while (true) {
			String tryName = MessageFormat.format("{0} ({1})", name, i);
			if (!keyStore.containsAlias(tryName)) {
				return tryName;
			}
			i++;
		}
	}
}
