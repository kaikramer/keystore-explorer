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

import javax.swing.ImageIcon;

import org.kse.gui.KseFrame;
import org.kse.gui.tipoftheday.DTipOfTheDay;

/**
 * Action to display a tip of the day.
 *
 */
public class TipOfTheDayAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public TipOfTheDayAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("TipOfTheDayAction.statusbar"));
		putValue(NAME, res.getString("TipOfTheDayAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("TipOfTheDayAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("TipOfTheDayAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		showTipOfTheDay();
	}

	/**
	 * Display the tip of the day dialog.
	 */
	public void showTipOfTheDay() {
		DTipOfTheDay dTipOfTheDay = new DTipOfTheDay(frame, applicationSettings.getShowTipsOnStartUp(), res,
				applicationSettings.getNextTipIndex());

		dTipOfTheDay.setLocationRelativeTo(frame);
		dTipOfTheDay.setVisible(true);

		applicationSettings.setShowTipsOnStartUp(dTipOfTheDay.showTipsOnStartup());
		applicationSettings.setNextTipIndex(dTipOfTheDay.nextTipIndex());
	}
}
