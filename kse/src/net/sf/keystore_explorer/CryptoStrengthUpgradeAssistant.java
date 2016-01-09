/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2016 Kai Kramer
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
package net.sf.keystore_explorer;

import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.UIManager;

import net.sf.keystore_explorer.gui.KseRestart;
import net.sf.keystore_explorer.gui.crypto.DUpgradeCryptoStrength;

public class CryptoStrengthUpgradeAssistant {

	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/resources");

	public static void main(String[] args) throws Exception {

		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

		// for restart of KSE
		System.setProperty("kse.install.dir", System.getProperty("user.dir"));

		DUpgradeCryptoStrength dUpgradeCryptoStrength = new DUpgradeCryptoStrength(new JFrame());
		dUpgradeCryptoStrength.setLocationRelativeTo(null);
		dUpgradeCryptoStrength.setVisible(true);

		if (dUpgradeCryptoStrength.hasCryptoStrengthBeenUpgraded()) {
			// Crypto strength upgraded - restart required to take effect
			JOptionPane.showMessageDialog(new JFrame(), res.getString("CryptoStrengthUpgrade.Upgraded.message"),
					KSE.getApplicationName(), JOptionPane.INFORMATION_MESSAGE);

			KseRestart.restart();
			System.exit(0);
		} else if (dUpgradeCryptoStrength.hasCryptoStrengthUpgradeFailed()) {
			// Manual install instructions have already been displayed
			System.exit(1);
		} else {
			// Crypto strength not upgraded - exit as upgrade required
			JOptionPane.showMessageDialog(new JFrame(), res.getString("CryptoStrengthUpgrade.NotUpgraded.message"),
					KSE.getApplicationName(), JOptionPane.WARNING_MESSAGE);

			System.exit(1);
		}
	}
}
