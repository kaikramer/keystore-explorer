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
package org.kse.gui;

import java.awt.SplashScreen;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import org.apache.commons.io.IOUtils;
import org.kse.ApplicationSettings;
import org.kse.AuthorityCertificates;
import org.kse.KSE;
import org.kse.crypto.jcepolicy.JcePolicyUtil;
import org.kse.gui.actions.CheckUpdateAction;
import org.kse.gui.crypto.DUpgradeCryptoStrength;
import org.kse.gui.dnd.DroppedFileHandler;
import org.kse.gui.error.DError;
import org.kse.utilities.net.URLs;
import org.kse.utilities.os.OperatingSystem;
import org.kse.version.JavaVersion;
import org.kse.version.Version;
import org.kse.version.VersionException;

/**
 * Runnable to create and show KeyStore Explorer application.
 */
public class CreateApplicationGui implements Runnable {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

	private static final JavaVersion MIN_JRE_VERSION = JavaVersion.JRE_VERSION_170;
	private ApplicationSettings applicationSettings;
	private SplashScreen splash;
	private List<File> parameterFiles;


	/**
	 * Construct CreateApplicationGui.
	 *
	 * @param applicationSettings Application settings
	 * @param splash              Splash screen
	 * @param parameterFiles      File list to open
	 */
	public CreateApplicationGui(ApplicationSettings applicationSettings, SplashScreen splash, List<File>
	parameterFiles) {
		this.applicationSettings = applicationSettings;
		this.splash = splash;
		this.parameterFiles = parameterFiles;
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

			// try to remove crypto restrictions
			JcePolicyUtil.removeRestrictions();

			// if crypto strength still limited, start upgrade assistant
			if (JcePolicyUtil.isLocalPolicyCrytoStrengthLimited()) {
				upgradeCryptoStrength();
			}

			final KseFrame kseFrame = new KseFrame();

			// workaround to a bug in initializing JEditorPane that seems to be a 1-in-10000 problem
			if (Thread.currentThread().getContextClassLoader() == null) {
				Thread.currentThread().setContextClassLoader(ClassLoader.getSystemClassLoader());
			}

			if (OperatingSystem.isMacOs()) {
				integrateWithMacOs(kseFrame);
			}

			kseFrame.display();

			// check if stored location of cacerts file still exists
			checkCaCerts(kseFrame);

			// open file list passed via command line params (basically same as if files were dropped on application)
			DroppedFileHandler.openFiles(kseFrame, parameterFiles);

			// start update check in background (disabled if KSE was packaged as rpm)
			if (!Boolean.getBoolean(KseFrame.KSE_UPDATE_CHECK_DISABLED)) {
				checkForUpdates(kseFrame);
			}
		} catch (Throwable t) {
			DError dError = new DError(new JFrame(), t);
			dError.setLocationRelativeTo(null);
			dError.setVisible(true);
			System.exit(1);
		} finally {
			closeSplash();
		}

	}

	private void checkCaCerts(final KseFrame kseFrame) {

		File caCertificatesFile = applicationSettings.getCaCertificatesFile();

		if (caCertificatesFile.exists()) {
			return;
		}

		// cacerts file is not where we expected it => detect location and inform user
		final File newCaCertsFile = new File(AuthorityCertificates.getDefaultCaCertificatesLocation().toString());

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				int selected = JOptionPane.showConfirmDialog(kseFrame.getUnderlyingFrame(), MessageFormat.format(
						res.getString("CreateApplicationGui.CaCertsFileNotFound.message"), newCaCertsFile), KSE
						.getApplicationName(), JOptionPane.YES_NO_OPTION);

				if (selected == JOptionPane.YES_OPTION) {
					applicationSettings.setCaCertificatesFile(newCaCertsFile);
				}
			}
		});
	}

	private void checkForUpdates(final KseFrame kseFrame) {
		new Thread() {
			@Override
			public void run() {
				try {
					// Get the version number of the latest KeyStore Explorer from its web site
					URL latestVersionUrl = new URL(URLs.LATEST_VERSION_ADDRESS);

					String versionString = IOUtils.toString(latestVersionUrl, "ASCII");
					final Version latestVersion = new Version(versionString);

					// show update dialog to user
					SwingUtilities.invokeLater(new Runnable() {
						@Override
						public void run() {
							CheckUpdateAction checkUpdateAction = new CheckUpdateAction(kseFrame);
							checkUpdateAction.compareVersions(latestVersion, true);
						}
					});
				} catch (Exception e) {
					// ignore any problems here
				}
			}
		}.start();
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

	private void upgradeCryptoStrength() {
		closeSplash();

		JOptionPane.showMessageDialog(new JFrame(), res.getString("CryptoStrengthUpgrade.UpgradeRequired.message"),
				KSE.getApplicationName(), JOptionPane.INFORMATION_MESSAGE);

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

	private void integrateWithMacOs(KseFrame kseFrame) throws ClassNotFoundException, SecurityException,
	NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException,
	InvocationTargetException {
		MacOsIntegration macOsIntegration = new MacOsIntegration(kseFrame);
		macOsIntegration.addEventHandlers();
	}

	private void closeSplash() {
		// May not be available or visible
		if (splash != null && splash.isVisible()) {
			splash.close();
		}
	}
}
