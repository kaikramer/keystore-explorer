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
import java.awt.event.InputEvent;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DExamineSsl;
import net.sf.keystore_explorer.gui.dialogs.DExaminingSsl;
import net.sf.keystore_explorer.gui.dialogs.DViewCertificate;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.ssl.SslConnectionInfos;

/**
 * Action to examine an SSL connection's certificates.
 *
 */
public class ExamineSslAction extends KeyStoreExplorerAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExamineSslAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(
				ACCELERATOR_KEY,
				KeyStroke.getKeyStroke(res.getString("ExamineSslAction.accelerator").charAt(0), Toolkit
						.getDefaultToolkit().getMenuShortcutKeyMask() + InputEvent.ALT_MASK));
		putValue(LONG_DESCRIPTION, res.getString("ExamineSslAction.statusbar"));
		putValue(NAME, res.getString("ExamineSslAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExamineSslAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ExamineSslAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			DExamineSsl dExamineSsl = new DExamineSsl(frame, kseFrame);
			dExamineSsl.setLocationRelativeTo(frame);
			dExamineSsl.setVisible(true);

			String sslHost = dExamineSsl.getSslHost();
			int sslPort = dExamineSsl.getSslPort();
			boolean useClientAuth = dExamineSsl.useClientAuth();
			KeyStoreHistory ksh = dExamineSsl.getKeyStore();

			if (dExamineSsl.wasCancelled()) {
				return;
			}

			DExaminingSsl dExaminingSsl = new DExaminingSsl(frame, sslHost, sslPort, useClientAuth, ksh);
			dExaminingSsl.setLocationRelativeTo(frame);
			dExaminingSsl.startExamination();
			dExaminingSsl.setVisible(true);

			SslConnectionInfos sslInfos = dExaminingSsl.getSSLConnectionInfos();

			if (sslInfos == null || sslInfos.getServerCertificates() == null) {
				return;
			}

			DViewCertificate dViewCertificate = new DViewCertificate(frame, MessageFormat.format(
					res.getString("ExamineSslAction.CertDetailsSsl.Title"), sslHost, Integer.toString(sslPort)),
					sslInfos.getServerCertificates(), kseFrame, DViewCertificate.IMPORT);
			dViewCertificate.setLocationRelativeTo(frame);
			dViewCertificate.setVisible(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
