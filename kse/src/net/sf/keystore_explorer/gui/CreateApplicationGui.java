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
package net.sf.keystore_explorer.gui;

import static java.awt.Dialog.ModalityType.DOCUMENT_MODAL;

import java.awt.Font;
import java.awt.SplashScreen;
import java.awt.Toolkit;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.UIManager;

import net.sf.keystore_explorer.ApplicationSettings;
import net.sf.keystore_explorer.KSE;
import net.sf.keystore_explorer.crypto.jcepolicy.JcePolicyUtil;
import net.sf.keystore_explorer.gui.actions.OpenAction;
import net.sf.keystore_explorer.gui.crypto.DUpgradeCryptoStrength;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.gui.error.DProblem;
import net.sf.keystore_explorer.gui.error.Problem;
import net.sf.keystore_explorer.gui.licenseagreement.DLicenseAgreement;
import net.sf.keystore_explorer.utilities.os.OperatingSystem;
import net.sf.keystore_explorer.version.JavaVersion;
import net.sf.keystore_explorer.version.VersionException;

/**
 * Runnable to create and show KeyStore Explorer application.
 *
 */
public class CreateApplicationGui implements Runnable {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/resources");
	private static final JavaVersion MIN_JRE_VERSION = JavaVersion.JRE_VERSION_160;
	private static final String KSE_JAR_NAME = "kse.jar";
	private ApplicationSettings applicationSettings;
	private SplashScreen splash;
	private File keyStoreFile;


	/**
	 * Construct CreateApplicationGui.
	 *
	 * @param applicationSettings
	 *            Application settings
	 * @param splash
	 *            Splash screen
	 * @param keyStoreFile
	 *            KeyStore file to open initially (supply null if none)
	 */
	public CreateApplicationGui(ApplicationSettings applicationSettings, SplashScreen splash, File keyStoreFile) {
		this.applicationSettings = applicationSettings;
		this.splash = splash;
		this.keyStoreFile = keyStoreFile;
	}

	/**
	 * Create and show KeyStore Explorer.
	 */
	@Override
	public void run() {
		try {
			if (!checkJreVersion()) {
				System.exit(1);
			}

			initLookAndFeel(applicationSettings);
			//setDefaultSize(14);

			if (!applicationSettings.getLicenseAgreed()) {
				displayLicenseAgreement(applicationSettings);
			}

			if (JcePolicyUtil.isLocalPolicyCrytoStrengthLimited()) {
				upgradeCryptoStrength();
			}

			final KseFrame kseFrame = new KseFrame();

			if (OperatingSystem.isMacOs()) {
				integrateWithMacOs(kseFrame);
			}

			kseFrame.display();

			if (keyStoreFile != null) {
				OpenAction openAction = new OpenAction(kseFrame);
				openAction.openKeyStore(keyStoreFile);
			}
		} catch (Throwable t) {
			DError dError = new DError(new JFrame(), DOCUMENT_MODAL, t);
			dError.setLocationRelativeTo(null);
			dError.setVisible(true);
			System.exit(1);
		} finally {
			closeSplash();
		}

	}

	private static void setDefaultSize(int size) {
		Set<Object> keySet = UIManager.getLookAndFeelDefaults().keySet();
		Object[] keys = keySet.toArray(new Object[keySet.size()]);

		for (Object key : keys) {
			if (key != null && key.toString().toLowerCase().contains("font")) {
				Font font = UIManager.getDefaults().getFont(key);
				if (font != null) {
					font = font.deriveFont((float) size);
					UIManager.put(key, font);
				}
			}
		}
	}


	private static void initLookAndFeel(ApplicationSettings applicationSettings) {
		LnfUtil.installLnfs();

		String lookFeelClassName = applicationSettings.getLookAndFeelClass();

		if (lookFeelClassName != null) {
			LnfUtil.useLnf(lookFeelClassName);
		} else {
			String lookAndFeelClass = LnfUtil.useLnfForPlatform();
			applicationSettings.setLookAndFeelClass(lookAndFeelClass);
		}

		boolean lookFeelDecorated = applicationSettings.getLookAndFeelDecorated();

		JFrame.setDefaultLookAndFeelDecorated(lookFeelDecorated);
		JDialog.setDefaultLookAndFeelDecorated(lookFeelDecorated);
	}


	private static boolean checkJreVersion() {
		JavaVersion actualJreVersion = null;

		try {
			actualJreVersion = JavaVersion.getJreVersion();
		} catch (VersionException ex) {
			String message = res.getString("CreateApplicationGui.NoParseJreVersion.message");
			System.err.println(message);
			JOptionPane.showMessageDialog(new JFrame(), message, KSE.getApplicationName(), JOptionPane.ERROR_MESSAGE);
			return false;
		}

		if (actualJreVersion.compareTo(MIN_JRE_VERSION) < 0) {
			String message = MessageFormat.format(res.getString("CreateApplicationGui.MinJreVersionReq.message"),
					actualJreVersion, MIN_JRE_VERSION);
			System.err.println(message);
			JOptionPane.showMessageDialog(new JFrame(), message, KSE.getApplicationName(), JOptionPane.ERROR_MESSAGE);
			return false;
		}

		return true;
	}

	private void displayLicenseAgreement(ApplicationSettings applicationSettings) throws IOException {
		closeSplash();

		String subject = KSE.getApplicationName();
		Icon licenseAgreementIcon = new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("LicenseAgreement.image"))));
		URL licenseAgreementUrl = getClass().getResource(res.getString("LicenseAgreement.Html"));

		DLicenseAgreement dLicenseAgreement = new DLicenseAgreement(new JFrame(), subject, licenseAgreementIcon,
				licenseAgreementUrl);
		dLicenseAgreement.setLocationRelativeTo(null);
		dLicenseAgreement.setVisible(true);

		if (!dLicenseAgreement.agreed()) {
			JOptionPane
					.showMessageDialog(
							new JFrame(),
							MessageFormat.format(res.getString("LicenseAgreement.NotAgreed.message"),
									KSE.getApplicationName()), KSE.getApplicationName(), JOptionPane.WARNING_MESSAGE);
			System.exit(1);
		}

		applicationSettings.setLicenseAgreed(true);
	}

	private void upgradeCryptoStrength() {
		closeSplash();

		JOptionPane.showMessageDialog(new JFrame(), res.getString("CryptoStrengthUpgrade.UpgradeRequired.message"),
				KSE.getApplicationName(), JOptionPane.INFORMATION_MESSAGE);

		if (OperatingSystem.isWindows()) {

			// start upgrade assistant with elevated permissions
			File kseInstallDir = new File(System.getProperty("kse.install.dir"));
			File cuaExe = new File(kseInstallDir, "cua.exe");

			// cmd.exe is workaround for http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6410605
			String toExec[] = new String[] { "cmd.exe", "/C", cuaExe.getPath() };

			try {
				Process process = Runtime.getRuntime().exec(toExec);
			} catch (Exception ex) {
	            Problem problem = new Problem("Cannot run Crypto Strength Upgrade Assistant.", null, ex);
	            JFrame frame = new JFrame();
				DProblem dProblem = new DProblem(frame, res.getString("ExamineFileAction.ProblemOpeningCrl.Title"),
	                    DOCUMENT_MODAL, problem);
	            dProblem.setLocationRelativeTo(frame);
	            dProblem.setVisible(true);
			} finally {
				System.exit(0);
			}

		} else {

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

	private void integrateWithMacOs(KseFrame kseFrame) throws ClassNotFoundException, SecurityException,
			NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException,
			InvocationTargetException {
		// Integration done by reflection to avoid Mac specific classes it
		// depends on being loaded on other platforms
		Class<?> macOsApplication = ClassLoader.getSystemClassLoader().loadClass(
				"net.sf.keystore_explorer.gui.MacOsIntegration");
		Constructor constructor = macOsApplication.getConstructor(KseFrame.class);
		constructor.newInstance(new Object[] { kseFrame });
	}

	private void closeSplash() {
		// May not be available or visible
		if (splash != null && splash.isVisible()) {
			splash.close();
		}
	}
}
