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

import java.awt.Desktop;
import java.awt.Toolkit;
import java.io.IOException;
import java.net.URI;
import java.text.MessageFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.KSE;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DCheckUpdate;
import org.kse.gui.error.DError;
import org.kse.utilities.net.URLs;
import org.kse.version.Version;
import org.kse.version.VersionException;

/**
 * Action to check for updates to KeyStore Explorer.
 *
 */
public class CheckUpdateAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public CheckUpdateAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("CheckUpdateAction.statusbar"));
		putValue(NAME, res.getString("CheckUpdateAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("CheckUpdateAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("CheckUpdateAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		DCheckUpdate dCheckUpdate = new DCheckUpdate(frame);
		dCheckUpdate.setLocationRelativeTo(frame);
		dCheckUpdate.startCheck();
		dCheckUpdate.setVisible(true);

		Version latestVersion = dCheckUpdate.getLatestVersion();

		if (latestVersion == null) {
			return;
		}

		compareVersions(latestVersion, false);
	}

	public void compareVersions(Version latestVersion, boolean autoUpdateCheck) {

		// abort auto update check if not time yet
		if (autoUpdateCheck) {
			if (!applicationSettings.isAutoUpdateCheckEnabled()) {
				return;
			}
			Date lastCheck = applicationSettings.getAutoUpdateCheckLastCheck();
			Date now = new Date();
			int checkInterval = applicationSettings.getAutoUpdateCheckInterval();
			if (TimeUnit.MILLISECONDS.toDays(now.getTime() - lastCheck.getTime()) < checkInterval) {
				return;
			} else {
				// save when last check happened
				applicationSettings.setAutoUpdateCheckLastCheck(new Date());
			}
		}

		try {
			Version currentVersion = KSE.getApplicationVersion();

			if (currentVersion.compareTo(latestVersion) >= 0) {
				if (!autoUpdateCheck) {
					JOptionPane.showMessageDialog(frame, MessageFormat.format(
							res.getString("CheckUpdateAction.HaveLatestVersion.message"), currentVersion), KSE
							.getApplicationName(), JOptionPane.INFORMATION_MESSAGE);
				}
			} else {

				int selected = JOptionPane.showConfirmDialog(frame, MessageFormat.format(
						res.getString("CheckUpdateAction.NewerVersionAvailable.message"), latestVersion), KSE
						.getApplicationName(), JOptionPane.YES_NO_OPTION);

				if (selected == JOptionPane.YES_OPTION) {
					openDownloadWebSite();
				}
			}
		} catch (VersionException ex) {
			DError.displayError(frame, ex);
		}
	}

	private void openDownloadWebSite() {
		try {
			Desktop.getDesktop().browse(URI.create(URLs.DOWNLOADS_WEB_ADDRESS));
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(frame, MessageFormat.format(
					res.getString("CheckUpdateAction.NoLaunchBrowser.message"),
					URLs.DOWNLOADS_WEB_ADDRESS), KSE.getApplicationName(), JOptionPane.INFORMATION_MESSAGE);
		}
	}
}
