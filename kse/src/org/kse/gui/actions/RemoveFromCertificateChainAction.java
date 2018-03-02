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
import java.security.cert.X509Certificate;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.Password;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to remove from the selected key pair entry's certificate chain.
 *
 */
public class RemoveFromCertificateChainAction extends KeyStoreExplorerAction implements HistoryAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public RemoveFromCertificateChainAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("RemoveFromCertificateChainAction.statusbar"));
		putValue(NAME, res.getString("RemoveFromCertificateChainAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("RemoveFromCertificateChainAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("RemoveFromCertificateChainAction.image")))));
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
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			String alias = kseFrame.getSelectedEntryAlias();

			Password password = getEntryPassword(alias, currentState);

			if (password == null) {
				return;
			}

			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();

			Key privKey = keyStore.getKey(alias, password.toCharArray());

			X509Certificate[] certChain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore
					.getCertificateChain(alias)));

			if (certChain.length == 1) {
				JOptionPane.showMessageDialog(frame,
						res.getString("RemoveFromCertificateChainAction.CannotRemoveOnlyCert.message"),
						res.getString("RemoveFromCertificateChainAction.RemoveFromCertificateChain.Title"),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			// Certificate to remove is the end one in the chain
			X509Certificate[] newCertChain = new X509Certificate[certChain.length - 1];

			System.arraycopy(certChain, 0, newCertChain, 0, newCertChain.length);

			keyStore.deleteEntry(alias);

			keyStore.setKeyEntry(alias, privKey, password.toCharArray(), newCertChain);

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane.showMessageDialog(frame,
					res.getString("RemoveFromCertificateChainAction.RemoveFromCertificateChainSuccessful.message"),
					res.getString("RemoveFromCertificateChainAction.RemoveFromCertificateChain.Title"),
					JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
