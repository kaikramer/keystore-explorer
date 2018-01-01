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
import java.io.File;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;
import javax.swing.UIManager;

import org.kse.ApplicationSettings;
import org.kse.AuthorityCertificates;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DPreferences;

/**
 * Action to show preferences.
 *
 */
public class PreferencesAction extends ExitAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public PreferencesAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("PreferencesAction.accelerator").charAt(0),
				Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("PreferencesAction.statusbar"));
		putValue(NAME, res.getString("PreferencesAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("PreferencesAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("PreferencesAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		showPreferences();
	}

	/**
	 * Display the preferences dialog and store the user's choices.
	 */
	public void showPreferences() {
		ApplicationSettings applicationSettings = ApplicationSettings.getInstance();

		File caCertificatesFile = applicationSettings.getCaCertificatesFile();

		DPreferences dPreferences = new DPreferences(frame, applicationSettings.getUseCaCertificates(),
				caCertificatesFile, applicationSettings.getUseWindowsTrustedRootCertificates(),
				applicationSettings.getEnableImportTrustedCertTrustCheck(),
				applicationSettings.getEnableImportCaReplyTrustCheck(), applicationSettings.getPasswordQualityConfig(),
				applicationSettings.getDefaultDN());
		dPreferences.setLocationRelativeTo(frame);
		dPreferences.setVisible(true);

		if (dPreferences.wasCancelled()) {
			return;
		}

		File tmpFile = dPreferences.getCaCertificatesFile();

		if (!tmpFile.equals(caCertificatesFile)) {
			AuthorityCertificates authorityCertificates = AuthorityCertificates.getInstance();
			authorityCertificates.setCaCertificates(null);
		}

		caCertificatesFile = tmpFile;

		applicationSettings.setCaCertificatesFile(caCertificatesFile);
		applicationSettings.setUseCaCertificates(dPreferences.getUseCaCertificates());
		applicationSettings.setUseWindowsTrustedRootCertificates(dPreferences.getUseWinTrustRootCertificates());
		applicationSettings.setEnableImportTrustedCertTrustCheck(dPreferences.getEnableImportTrustedCertTrustCheck());
		applicationSettings.setEnableImportCaReplyTrustCheck(dPreferences.getEnableImportCaReplyTrustCheck());
		applicationSettings.setPasswordQualityConfig(dPreferences.getPasswordQualityConfig());
		applicationSettings.setDefaultDN(dPreferences.getDefaultDN());

		UIManager.LookAndFeelInfo lookFeelInfo = dPreferences.getLookFeelInfo();
		applicationSettings.setLookAndFeelClass(lookFeelInfo.getClassName());

		boolean lookAndFeelDecorated = dPreferences.getLookFeelDecoration();
		applicationSettings.setLookAndFeelDecorated(lookAndFeelDecorated);

		if ((!lookFeelInfo.getClassName().equals(UIManager.getLookAndFeel().getClass().getName()))
				|| (lookAndFeelDecorated != JFrame.isDefaultLookAndFeelDecorated())) {
			// L&F changed - restart required for upgrade to take effect
			JOptionPane.showMessageDialog(frame, res.getString("PreferencesAction.LookFeelChanged.message"),
					res.getString("PreferencesAction.LookFeelChanged.Title"), JOptionPane.INFORMATION_MESSAGE);

			exitApplication(true);
		}
	}
}
