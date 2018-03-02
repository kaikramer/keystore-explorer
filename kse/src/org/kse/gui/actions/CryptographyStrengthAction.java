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
import org.kse.gui.crypto.DCryptoStrength;
import org.kse.gui.error.DError;

/**
 * Action to display the Cryptography Strength dialog.
 *
 */
public class CryptographyStrengthAction extends ExitAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public CryptographyStrengthAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, null); // Blank the accelerators set above in
		// the class hierarchy
		putValue(LONG_DESCRIPTION, res.getString("CryptographyStrengthAction.statusbar"));
		putValue(NAME, res.getString("CryptographyStrengthAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("CryptographyStrengthAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("CryptographyStrengthAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			DCryptoStrength dCryptoStrength = new DCryptoStrength(frame);
			dCryptoStrength.setLocationRelativeTo(frame);
			dCryptoStrength.setVisible(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
