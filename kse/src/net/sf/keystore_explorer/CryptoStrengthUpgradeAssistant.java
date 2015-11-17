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
