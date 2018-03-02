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
import java.net.URL;
import java.text.MessageFormat;

import javax.swing.ImageIcon;

import org.kse.KSE;
import org.kse.gui.KseFrame;
import org.kse.gui.LnfUtil;
import org.kse.gui.about.DAbout;

/**
 * Action to show KeyStore Explorer about dialog.
 *
 */
public class AboutAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public AboutAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("AboutAction.statusbar"));
		putValue(NAME, res.getString("AboutAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("AboutAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("AboutAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		showAbout();
	}

	/**
	 * Display the about dialog.
	 */
	public void showAbout() {
		Object[] tickerItems = { res.getString("AboutAction.Copyright"), res.getString("AboutAction.Acknowledgement1"),
				res.getString("AboutAction.Acknowledgement2"), res.getString("AboutAction.Acknowledgement3"),
				res.getString("AboutAction.Acknowledgement4"), res.getString("AboutAction.Acknowledgement5"),
				res.getString("AboutAction.Acknowledgement6"), res.getString("AboutAction.Acknowledgement7"),
				LnfUtil.isDarculaAvailable() ? res.getString("AboutAction.Acknowledgement8") : "",
		};

		URL aboutDialogImageURL = AboutAction.class.getResource(res.getString("AboutAction.About.image"));
		DAbout dAbout = new DAbout(frame,
				MessageFormat.format(res.getString("AboutAction.About.Title"), KSE.getApplicationName()),
				res.getString("AboutAction.License"),
				Toolkit.getDefaultToolkit().createImage(aboutDialogImageURL), tickerItems);
		dAbout.setLocationRelativeTo(frame);
		dAbout.setVisible(true);
	}
}
