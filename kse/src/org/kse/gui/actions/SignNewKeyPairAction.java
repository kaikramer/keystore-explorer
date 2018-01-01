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
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.swing.ImageIcon;

import org.kse.crypto.Password;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to sign a newly generated key pair (i.e. generate a certificate) using the selected key pair entry as issuing
 * CA.
 *
 */
public class SignNewKeyPairAction extends KeyStoreExplorerAction {

	private static final long serialVersionUID = 6130302168441299361L;

	public SignNewKeyPairAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("SignNewKeyPairAction.statusbar"));
		putValue(NAME, res.getString("SignNewKeyPairAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SignNewKeyPairAction.tooltip"));
		putValue(SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("SignNewKeyPairAction.image")))));
	}

	@Override
	protected void doAction() {

		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			// get alias of selected (signing) key entry
			String alias = kseFrame.getSelectedEntryAlias();

			Password password = getEntryPassword(alias, currentState);
			if (password == null) {
				return;
			}

			KeyStore keyStore = currentState.getKeyStore();
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			Certificate[] certs = keyStore.getCertificateChain(alias);

			X509Certificate[] signingCertChain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));
			X509Certificate signingCert = signingCertChain[0];

			GenerateKeyPairAction generateKeyPairAction = new GenerateKeyPairAction(kseFrame);
			generateKeyPairAction.generateKeyPair(signingCert, signingCertChain, privateKey);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

}
