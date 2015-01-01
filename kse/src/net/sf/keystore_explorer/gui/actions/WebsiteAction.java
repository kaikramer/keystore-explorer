/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2015 Kai Kramer
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

import java.awt.Desktop;
import java.awt.Toolkit;
import java.io.IOException;
import java.net.URI;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import net.sf.keystore_explorer.KSE;
import net.sf.keystore_explorer.gui.KseFrame;

/**
 * Action to visit the KeyStore Explorer web site.
 *
 */
public class WebsiteAction extends KeyStoreExplorerAction {

    private String websiteAddress;

    public enum Target {
        MAIN,
        SOURCEFORGE,
        BUGREPORTS,
        FEATURE_REQUESTS,
        FORUM
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
        case SOURCEFORGE:
            setData(res.getString("WebsiteAction.SourceforgeProject.statusbar"),
                    res.getString("WebsiteAction.SourceforgeProject.text"),
                    res.getString("WebsiteAction.SourceforgeProject.tooltip"),
                    res.getString("WebsiteAction.image"),
                    res.getString("WebsiteAction.SourceforgeProject.KseWebAddress"));
            break;
        case BUGREPORTS:
            setData(res.getString("WebsiteAction.BugReports.statusbar"),
                    res.getString("WebsiteAction.BugReports.text"),
                    res.getString("WebsiteAction.BugReports.tooltip"),
                    res.getString("WebsiteAction.image"),
                    res.getString("WebsiteAction.BugReports.KseWebAddress"));
            break;
        case FEATURE_REQUESTS:
            setData(res.getString("WebsiteAction.FeatureRequests.statusbar"),
                    res.getString("WebsiteAction.FeatureRequests.text"),
                    res.getString("WebsiteAction.FeatureRequests.tooltip"),
                    res.getString("WebsiteAction.image"),
                    res.getString("WebsiteAction.FeatureRequests.KseWebAddress"));
            break;
        case FORUM:
            setData(res.getString("WebsiteAction.Forum.statusbar"),
                    res.getString("WebsiteAction.Forum.text"),
                    res.getString("WebsiteAction.Forum.tooltip"),
                    res.getString("WebsiteAction.image"),
                    res.getString("WebsiteAction.Forum.KseWebAddress"));
            break;
        default:
        case MAIN:
            setData(res.getString("WebsiteAction.statusbar"),
                    res.getString("WebsiteAction.text"),
                    res.getString("WebsiteAction.tooltip"),
                    res.getString("WebsiteAction.image"),
                    res.getString("WebsiteAction.KseWebAddress"));
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
