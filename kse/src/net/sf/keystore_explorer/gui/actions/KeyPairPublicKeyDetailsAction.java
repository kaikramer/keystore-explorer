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

import net.sf.keystore_explorer.crypto.x509.X509CertUtil;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DViewPublicKey;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.history.KeyStoreState;

/**
 * Action to display the public key details for the selected key pair entry.
 *
 */
public class KeyPairPublicKeyDetailsAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public KeyPairPublicKeyDetailsAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("KeyPairPublicKeyDetailsAction.statusbar"));
		putValue(NAME, res.getString("KeyPairPublicKeyDetailsAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("KeyPairPublicKeyDetailsAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("KeyPairPublicKeyDetailsAction.image")))));
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

			PublicKey pubKey = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore
					.getCertificateChain(alias)))[0].getPublicKey();

			DViewPublicKey dViewPublicKey = new DViewPublicKey(frame, MessageFormat.format(
					res.getString("KeyPairPublicKeyDetailsAction.PubKeyDetailsEntry.Title"), alias), pubKey);
			dViewPublicKey.setLocationRelativeTo(frame);
			dViewPublicKey.setVisible(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
