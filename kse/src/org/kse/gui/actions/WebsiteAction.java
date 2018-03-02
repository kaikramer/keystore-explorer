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

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.KSE;
import org.kse.gui.KseFrame;
import org.kse.utilities.net.URLs;

/**
 * Action to visit the KeyStore Explorer web site.
 *
 */
public class WebsiteAction extends KeyStoreExplorerAction {

	private static final long serialVersionUID = 1L;
	private String websiteAddress;

	public enum Target {
		MAIN,
		GITHUB,
		ISSUE_TRACKER
	}

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public WebsiteAction(KseFrame kseFrame, Target target) {
		super(kseFrame);

		switch (target) {
		case GITHUB:
			setData(res.getString("WebsiteAction.GitHubProject.statusbar"),
					res.getString("WebsiteAction.GitHubProject.text"),
					res.getString("WebsiteAction.GitHubProject.tooltip"),
					res.getString("WebsiteAction.image"),
					URLs.GITHUB_PROJECT);
			break;
		case ISSUE_TRACKER:
			setData(res.getString("WebsiteAction.GitHubIssueTracker.statusbar"),
					res.getString("WebsiteAction.GitHubIssueTracker.text"),
					res.getString("WebsiteAction.GitHubIssueTracker.tooltip"),
					res.getString("WebsiteAction.image"),
					URLs.GITHUB_ISSUE_TRACKER);
			break;
		default:
		case MAIN:
			setData(res.getString("WebsiteAction.statusbar"),
					res.getString("WebsiteAction.text"),
					res.getString("WebsiteAction.tooltip"),
					res.getString("WebsiteAction.image"),
					URLs.KSE_WEB_SITE);
			break;
		}
	}

	private void setData(String longDescription, String name, String shortDescription, String image, String url) {
		putValue(LONG_DESCRIPTION, longDescription);
		putValue(NAME, name);
		putValue(SHORT_DESCRIPTION, shortDescription);
		putValue(SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(image))));

		websiteAddress = url;
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			Desktop.getDesktop().browse(URI.create(websiteAddress));
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(frame,
					MessageFormat.format(res.getString("WebsiteAction.NoLaunchBrowser.message"), websiteAddress),
					KSE.getApplicationName(), JOptionPane.INFORMATION_MESSAGE);
		}
	}
}
