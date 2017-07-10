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
 * Action to display the details for the selected trusted certificate entry.
 *
 */
public class TrustedCertificateDetailsAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public TrustedCertificateDetailsAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("TrustedCertificateDetailsAction.statusbar"));
		putValue(NAME, res.getString("TrustedCertificateDetailsAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("TrustedCertificateDetailsAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("TrustedCertificateDetailsAction.image")))));
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

			X509Certificate[] certs = new X509Certificate[1];
			certs[0] = X509CertUtil.convertCertificate(keyStore.getCertificate(alias));

			DViewCertificate dViewCertificate = new DViewCertificate(frame, MessageFormat.format(
					res.getString("TrustedCertificateDetailsAction.CertDetailsEntry.Title"), alias), certs,
					kseFrame, DViewCertificate.EXPORT);
			dViewCertificate.setLocationRelativeTo(frame);
			dViewCertificate.setVisible(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
