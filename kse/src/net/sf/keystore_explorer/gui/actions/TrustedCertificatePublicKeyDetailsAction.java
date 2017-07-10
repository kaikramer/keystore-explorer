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
import java.security.KeyStore;
import java.security.PublicKey;
import java.text.MessageFormat;

import javax.swing.ImageIcon;

import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DViewPublicKey;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.history.KeyStoreState;

/**
 * Action to display the public key details for the selected trusted certificate
 * entry.
 *
 */
public class TrustedCertificatePublicKeyDetailsAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public TrustedCertificatePublicKeyDetailsAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("TrustedCertificatePublicKeyDetailsAction.statusbar"));
		putValue(NAME, res.getString("TrustedCertificatePublicKeyDetailsAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("TrustedCertificatePublicKeyDetailsAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("TrustedCertificatePublicKeyDetailsAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			KeyStore keyStore = currentState.getKeyStore();
			String alias = kseFrame.getSelectedEntryAlias();

			PublicKey pubKey = keyStore.getCertificate(alias).getPublicKey();

			DViewPublicKey dViewPublicKey = new DViewPublicKey(frame, MessageFormat.format(
					res.getString("TrustedCertificatePublicKeyDetailsAction.PubKeyDetailsEntry.Title"), alias), pubKey);
			dViewPublicKey.setLocationRelativeTo(frame);
			dViewPublicKey.setVisible(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
