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
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;

import net.sf.keystore_explorer.crypto.x509.X509CertUtil;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DViewCertificate;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;

/**
 * Action to display the certificate chain details for the selected key pair
 * entry.
 *
 */
public class KeyPairCertificateChainDetailsAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public KeyPairCertificateChainDetailsAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("KeyPairCertificateChainDetailsAction.statusbar"));
		putValue(NAME, res.getString("KeyPairCertificateChainDetailsAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("KeyPairCertificateChainDetailsAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("KeyPairCertificateChainDetailsAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		showCertificateSelectedEntry();
	}

	/**
	 * Show the certificate details of the selected KeyStore entry.
	 */
	public void showCertificateSelectedEntry() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStore keyStore = history.getCurrentState().getKeyStore();
			String alias = kseFrame.getSelectedEntryAlias();

			X509Certificate[] certs = X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias));

			DViewCertificate dViewCertificate = new DViewCertificate(frame, MessageFormat.format(
					res.getString("KeyPairCertificateChainDetailsAction.CertDetailsEntry.Title"), alias), certs,
					kseFrame, DViewCertificate.EXPORT);
			dViewCertificate.setLocationRelativeTo(frame);
			dViewCertificate.setVisible(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
