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

import java.awt.Dialog.ModalExclusionType;
import java.awt.Dimension;
import java.awt.Image;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.KeyEvent;
import java.net.URL;
import java.util.ArrayList;

import javax.help.DefaultHelpBroker;
import javax.help.HelpSet;
import javax.help.HelpSetException;
import javax.help.WindowPresentation;
import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.gui.KseFrame;
import org.kse.gui.LnfUtil;
import org.kse.gui.error.DError;

/**
 * Action to show help.
 *
 */
public class HelpAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	private static final String START_ID = "introduction";

	private DefaultHelpBroker helpBroker;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public HelpAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0));
		putValue(LONG_DESCRIPTION, res.getString("HelpAction.statusbar"));
		putValue(NAME, res.getString("HelpAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("HelpAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("HelpAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			if (helpBroker != null) {
				if (helpBroker.isDisplayed()) {
					return; // Help already displayed
				}

				helpBroker.setDisplayed(true); // Help already created but
				// hidden - redisplay
				return;
			}

			createAndDisplayHelp();
		} catch (HelpSetException ex) {
			DError.displayError(frame, ex);
		}
	}

	private void createAndDisplayHelp() throws HelpSetException {
		URL hsUrl = getClass().getResource(res.getString("HelpAction.HelpSet"));
		HelpSet hs = new HelpSet(getClass().getClassLoader(), hsUrl);

		if (LnfUtil.isDarculaAvailable()) {
			URL hsDarculaUrl = getClass().getResource(res.getString("HelpAction.DarculaHelpSet"));
			HelpSet hsDarcula = new HelpSet(getClass().getClassLoader(), hsDarculaUrl);
			hs.add(hsDarcula);
		}

		helpBroker = new DefaultHelpBroker(hs);

		WindowPresentation windowPresentation = helpBroker.getWindowPresentation();
		windowPresentation.createHelpWindow();

		// Make window immune to modal dialogs in application
		Window helpWindow = windowPresentation.getHelpWindow();
		helpWindow.setModalExclusionType(ModalExclusionType.APPLICATION_EXCLUDE);

		// Set help icons - set lots of different sizes to give each OS the most
		// flexibility in choosing an icon for display
		ArrayList<Image> icons = new ArrayList<Image>();
		icons.add(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("HelpAction.image.16x16"))));
		icons.add(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("HelpAction.image.24x24"))));
		icons.add(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("HelpAction.image.32x32"))));

		helpWindow.setIconImages(icons);

		helpBroker.setLocation(new Point(frame.getX() + 25, frame.getY() + 25));
		helpBroker.setSize(new Dimension(850, 600));
		helpBroker.setCurrentID(START_ID);

		helpBroker.setDisplayed(true);
	}
}
