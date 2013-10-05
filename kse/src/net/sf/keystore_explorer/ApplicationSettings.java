/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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

import static net.sf.keystore_explorer.crypto.digest.DigestType.SHA1;
import static net.sf.keystore_explorer.crypto.keypair.KeyPairType.RSA;
import static net.sf.keystore_explorer.crypto.secretkey.SecretKeyType.AES;

import java.awt.Rectangle;
import java.io.File;
import java.net.ProxySelector;
import java.util.ArrayList;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import javax.swing.JTabbedPane;

import net.sf.keystore_explorer.crypto.digest.DigestType;
import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.crypto.secretkey.SecretKeyType;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.password.PasswordQualityConfig;
import net.sf.keystore_explorer.utilities.net.ManualProxySelector;
import net.sf.keystore_explorer.utilities.net.NoProxySelector;
import net.sf.keystore_explorer.utilities.net.PacProxySelector;
import net.sf.keystore_explorer.utilities.net.ProxyAddress;

/**
 * KSE Application settings. Load, save and provide access to the various
 * application settings. Settings persist to Java preferences.
 * 
 */
public class ApplicationSettings {
	private static ApplicationSettings applicationSettings;
	private boolean useCaCertificates;
	private File caCertificatesFile;
	private boolean useWindowsTrustedRootCertificates;
	private boolean enableImportTrustedCertTrustCheck;
	private boolean enableImportCaReplyTrustCheck;
	private KeyPairType generateKeyPairType;
	private int generateKeyPairSize;
	private SecretKeyType generateSecretKeyType;
	private int generateSecretKeySize;
	private DigestType certificateFingerprintType;
	private PasswordQualityConfig passwordQualityConfig;
	private Rectangle sizeAndPosition;
	private boolean showToolBar;
	private boolean showStatusBar;
	private int tabLayout;
	private File[] recentFiles;
	private File currentDirectory;
	private String lookAndFeelClass;
	private boolean lookAndFeelDecorated;
	private boolean licenseAgreed;
	private boolean showTipsOnStartUp;
	private int nextTipIndex;

	private ApplicationSettings() {

		// one-time conversion from old to new preferences location:
		Preferences root = Preferences.userRoot();
		try {
			// if preferences exist under /com/lazgosoftware but not under /net/sf/keystore_explorer ...
			if (root.nodeExists("/com/lazgosoftware") && !root.nodeExists("/net/sf/keystore_explorer")) {
				
				// ... then copy settings from old to new subtree 
				Preferences prefsOld = root.node("/com/lazgosoftware/utilities/kse");
				Preferences prefsNew = root.node("/net/sf/keystore_explorer");

				for (String key : prefsOld.keys()) {
					prefsNew.put(key, prefsOld.get(key, ""));
				}
				
				prefsNew.flush();
			}
		} catch (BackingStoreException e) {
			// ignore errors here
		}

		load();
	}

	/**
	 * Get singleton instance of application settings. If first call the
	 * application settings are loaded.
	 * 
	 * @return Application settings
	 */
	public static synchronized ApplicationSettings getInstance() {
		if (applicationSettings == null) {
			applicationSettings = new ApplicationSettings();
		}

		return applicationSettings;
	}

	/**
	 * Load application settings from persistant store.
	 */
	public void load() {
		Preferences preferences = getUnderlyingPreferences();

		//
		// Authority certificates
		//

		useCaCertificates = preferences.getBoolean("kse3.usecacerts", false);
		caCertificatesFile = new File(preferences.get("kse3.cacertsfile", AuthorityCertificates
				.getDefaultCaCertificatesLocation().toString()));
		useWindowsTrustedRootCertificates = preferences.getBoolean("kse3.usewintrustrootcerts", false);

		//
		// Trust checks
		//
		enableImportTrustedCertTrustCheck = preferences.getBoolean("kse3.enableimporttrustedcerttrustcheck", true);
		enableImportCaReplyTrustCheck = preferences.getBoolean("kse3.enableimportcareplytrustcheck", true);

		//
		// Key pair generation
		//

		generateKeyPairType = KeyPairType.resolveJce(preferences.get("kse3.keypairtype", RSA.jce()));
		if (generateKeyPairType == null) {
			generateKeyPairType = RSA;
		}

		int defaultKeyPairSize;

		if (generateKeyPairType == RSA) {
			defaultKeyPairSize = 2048;
		} else {
			defaultKeyPairSize = 1024; // DSA
		}

		generateKeyPairSize = preferences.getInt("kse3.keypairsize", defaultKeyPairSize);

		//
		// Secret key generation
		//

		generateSecretKeyType = SecretKeyType.resolveJce(preferences.get("kse3.seckeytype", AES.jce()));
		if (generateSecretKeyType == null) {
			generateSecretKeyType = AES;
		}

		generateSecretKeySize = preferences.getInt("kse3.seckeysize", 192);

		//
		// Certificate fingerprint
		//

		certificateFingerprintType = DigestType.resolveJce(preferences.get("kse3.certfingertype", SHA1.jce()));
		if (certificateFingerprintType == null) {
			certificateFingerprintType = SHA1;
		}

		//
		// Password quality
		//

		passwordQualityConfig = new PasswordQualityConfig(preferences.getBoolean("kse3.pwdqualenable", false),
				preferences.getBoolean("kse3.minpwdqualenforce", false), preferences.getInt("kse3.minpwdqual", 60));

		//
		// Internet proxy settings
		//

		String pacUrl = preferences.get("kse3.pacurl", null);

		if (pacUrl != null) {
			// Use PAC URL for proxy configuration
			ProxySelector.setDefault(new PacProxySelector(pacUrl));
		} else {
			// Use manual settings for HTTP, HTTPS and SOCKS proxies when
			// details are supplied
			ProxyAddress httpProxyAddress = null;
			ProxyAddress httpsProxyAddress = null;
			ProxyAddress socksProxyAddress = null;

			String httpHost = preferences.get("kse3.httphost", null);
			int httpPort = preferences.getInt("kse3.httpport", 0);

			if ((httpHost != null) && (httpPort > 0)) {
				httpProxyAddress = new ProxyAddress(httpHost, httpPort);
			}

			String httpsHost = preferences.get("kse3.httpshost", null);
			int httpsPort = preferences.getInt("kse3.httpsport", 0);

			if ((httpsHost != null) && (httpsPort > 0)) {
				httpsProxyAddress = new ProxyAddress(httpsHost, httpsPort);
			}

			String socksHost = preferences.get("kse3.sockshost", null);
			int socksPort = preferences.getInt("kse3.socksport", 0);

			if ((socksHost != null) && (socksPort > 0)) {
				socksProxyAddress = new ProxyAddress(socksHost, socksPort);
			}

			if ((httpProxyAddress != null) || (httpsProxyAddress != null)) {
				ProxySelector.setDefault(new ManualProxySelector(httpProxyAddress, httpsProxyAddress, null,
						socksProxyAddress));
			}
			// No PAC and no manual settings - use no proxy to connect to the
			// Internet
			else {
				ProxySelector.setDefault(new NoProxySelector());
			}
		}

		//
		// Application size and position
		//

		sizeAndPosition = new Rectangle(preferences.getInt("kse3.xpos", 0), preferences.getInt("kse3.ypos", 0),
				preferences.getInt("kse3.width", KseFrame.DEFAULT_WIDTH), preferences.getInt("kse3.height",
						KseFrame.DEFAULT_HEIGHT));

		//
		// User interface
		//

		showToolBar = preferences.getBoolean("kse3.showtoolbar", true);
		showStatusBar = preferences.getBoolean("kse3.showstatusbar", true);
		tabLayout = preferences.getInt("kse3.tablayout", JTabbedPane.WRAP_TAB_LAYOUT);

		//
		// Recent files
		//

		ArrayList<File> recentFilesList = new ArrayList<File>();

		for (int i = 1; i <= KseFrame.RECENT_FILES_SIZE; i++) {
			String recentFile = preferences.get("kse3.recentfile" + i, null);

			if (recentFile == null) {
				break;
			} else {
				recentFilesList.add(new File(recentFile));
			}
		}

		recentFiles = recentFilesList.toArray(new File[recentFilesList.size()]);

		//
		// Current directory
		//

		String currentDirectoryStr = preferences.get("kse3.currentdir", null);

		if (currentDirectoryStr != null) {
			currentDirectory = new File(currentDirectoryStr);
		}

		//
		// Look and feel
		//

		lookAndFeelClass = preferences.get("kse3.lookfeel", null);
		lookAndFeelDecorated = preferences.getBoolean("kse3.lookfeeldecor", false);

		//
		// Licensing
		//

		licenseAgreed = preferences.getBoolean("kse3.licenseagreed", false);

		//
		// Tip of the day
		//

		showTipsOnStartUp = preferences.getBoolean("kse3.tipsonstartup", true);
		nextTipIndex = preferences.getInt("kse3.tipindex", 0);
	}

	/**
	 * Save application settings to persistant store.
	 */
	public void save() {
		Preferences preferences = getUnderlyingPreferences();

		//
		// Authority certificates
		//

		preferences.putBoolean("kse3.usecacerts", useCaCertificates);
		preferences.put("kse3.cacertsfile", caCertificatesFile.toString());
		preferences.putBoolean("kse3.usewintrustrootcerts", useWindowsTrustedRootCertificates);

		//
		// Trust checks
		//
		preferences.putBoolean("kse3.enableimporttrustedcerttrustcheck", enableImportTrustedCertTrustCheck);
		preferences.putBoolean("kse3.enableimportcareplytrustcheck", enableImportCaReplyTrustCheck);

		//
		// Key pair generation
		//

		preferences.put("kse3.keypairtype", generateKeyPairType.jce());
		preferences.putInt("kse3.keypairsize", generateKeyPairSize);

		//
		// Secret key generation
		//

		preferences.put("kse3.seckeytype", generateSecretKeyType.jce());
		preferences.putInt("kse3.seckeysize", generateSecretKeySize);

		//
		// Certificate fingerprint
		//

		preferences.put("kse3.certfingertype", certificateFingerprintType.jce());

		//
		// Password quality
		//

		preferences.putBoolean("kse3.pwdqualenable", passwordQualityConfig.getEnabled());
		preferences.putBoolean("kse3.minpwdqualenforce", passwordQualityConfig.getEnforced());
		preferences.putInt("kse3.minpwdqual", passwordQualityConfig.getMinimumQuality());

		//
		// Internet proxy settings
		//

		// Clear all existing proxy settings in preferences
		preferences.remove("kse3.httphost");
		preferences.remove("kse3.httpport");
		preferences.remove("kse3.httpshost");
		preferences.remove("kse3.httpsport");
		preferences.remove("kse3.sockshost");
		preferences.remove("kse3.socksport");
		preferences.remove("kse3.pacurl");

		// Get current proxy settings
		ProxySelector proxySelector = ProxySelector.getDefault();

		if (proxySelector instanceof PacProxySelector) {
			PacProxySelector pacProxySelector = (PacProxySelector) proxySelector;

			preferences.put("kse3.pacurl", pacProxySelector.getPacUrl());
		} else if (proxySelector instanceof ManualProxySelector) {
			ManualProxySelector manualProxySelector = (ManualProxySelector) proxySelector;

			ProxyAddress httpProxyAddress = manualProxySelector.getHttpProxyAddress();
			if (httpProxyAddress != null) {
				preferences.put("kse3.httphost", httpProxyAddress.getHost());
				preferences.putInt("kse3.httpport", httpProxyAddress.getPort());
			}

			ProxyAddress httpsProxyAddress = manualProxySelector.getHttpsProxyAddress();
			if (httpsProxyAddress != null) {
				preferences.put("kse3.httpshost", httpsProxyAddress.getHost());
				preferences.putInt("kse3.httpsport", httpsProxyAddress.getPort());
			}

			ProxyAddress socksProxyAddress = manualProxySelector.getSocksProxyAddress();
			if (socksProxyAddress != null) {
				preferences.put("kse3.sockshost", socksProxyAddress.getHost());
				preferences.putInt("kse3.socksport", socksProxyAddress.getPort());
			}
		}

		// If nothing is set above use no proxy to connect to the Internet

		//
		// Application size and position
		//

		preferences.putInt("kse3.xpos", sizeAndPosition.x);
		preferences.putInt("kse3.ypos", sizeAndPosition.y);
		preferences.putInt("kse3.width", sizeAndPosition.width);
		preferences.putInt("kse3.height", sizeAndPosition.height);

		//
		// User interface
		//

		preferences.putBoolean("kse3.showtoolbar", showToolBar);
		preferences.putBoolean("kse3.showstatusbar", showStatusBar);
		preferences.putInt("kse3.tablayout", tabLayout);

		//
		// Recent files
		//

		// Clear all existing recent files (new list may be shorter than the
		// existing one)
		for (int i = 1; i <= KseFrame.RECENT_FILES_SIZE; i++) {
			String recentFile = preferences.get("kse3.recentfile" + i, null);

			if (recentFile == null) {
				break;
			} else {
				preferences.remove("kse3.recentfile" + i);
			}
		}

		for (int i = 1; i <= recentFiles.length; i++) {
			preferences.put("kse3.recentfile" + i, recentFiles[i - 1].toString());
		}

		//
		// Current directory
		//

		preferences.put("kse3.currentdir", currentDirectory.toString());

		//
		// Look and feel
		//

		preferences.put("kse3.lookfeel", lookAndFeelClass);
		preferences.putBoolean("kse3.lookfeeldecor", lookAndFeelDecorated);

		//
		// Licensing
		//

		preferences.putBoolean("kse3.licenseagreed", licenseAgreed);

		//
		// Tip of the day
		//

		preferences.putBoolean("kse3.tipsonstartup", showTipsOnStartUp);
		preferences.putInt("kse3.tipindex", nextTipIndex);
	}

	/**
	 * Clear application settings in persistent store.
	 * 
	 * @throws BackingStoreException
	 *             If a failure occurred in the backing store
	 */
	public void clear() throws BackingStoreException {
		Preferences preferences = getUnderlyingPreferences();
		preferences.clear();
	}

	private Preferences getUnderlyingPreferences() {
		// Get underlying Java preferences
		Preferences preferences = Preferences.userNodeForPackage(ApplicationSettings.class);
		return preferences;
	}

	public boolean getUseCaCertificates() {
		return useCaCertificates;
	}

	public void setUseCaCertificates(boolean useCaCertificates) {
		this.useCaCertificates = useCaCertificates;
	}

	public File getCaCertificatesFile() {
		return caCertificatesFile;
	}

	public void setCaCertificatesFile(File caCertificatesFile) {
		this.caCertificatesFile = caCertificatesFile;
	}

	public boolean getUseWindowsTrustedRootCertificates() {
		return useWindowsTrustedRootCertificates;
	}

	public void setUseWindowsTrustedRootCertificates(boolean useWindowsTrustedRootCertificates) {
		this.useWindowsTrustedRootCertificates = useWindowsTrustedRootCertificates;
	}

	public boolean getEnableImportTrustedCertTrustCheck() {
		return enableImportTrustedCertTrustCheck;
	}

	public void setEnableImportTrustedCertTrustCheck(boolean enableImportTrustedCertTrustCheck) {
		this.enableImportTrustedCertTrustCheck = enableImportTrustedCertTrustCheck;
	}

	public boolean getEnableImportCaReplyTrustCheck() {
		return enableImportCaReplyTrustCheck;
	}

	public void setEnableImportCaReplyTrustCheck(boolean enableImportCaReplyTrustCheck) {
		this.enableImportCaReplyTrustCheck = enableImportCaReplyTrustCheck;
	}

	public KeyPairType getGenerateKeyPairType() {
		return generateKeyPairType;
	}

	public void setGenerateKeyPairType(KeyPairType generateKeyPairType) {
		this.generateKeyPairType = generateKeyPairType;
	}

	public int getGenerateKeyPairSize() {
		return generateKeyPairSize;
	}

	public void setGenerateKeyPairSize(int generateKeyPairSize) {
		this.generateKeyPairSize = generateKeyPairSize;
	}

	public SecretKeyType getGenerateSecretKeyType() {
		return generateSecretKeyType;
	}

	public void setGenerateSecretKeyType(SecretKeyType generateSecretKeyType) {
		this.generateSecretKeyType = generateSecretKeyType;
	}

	public int getGenerateSecretKeySize() {
		return generateSecretKeySize;
	}

	public void setGenerateSecretKeySize(int generateSecretKeySize) {
		this.generateSecretKeySize = generateSecretKeySize;
	}

	public DigestType getCertificateFingerprintType() {
		return certificateFingerprintType;
	}

	public void setCertificateFingerprintType(DigestType certificateFingerprintType) {
		this.certificateFingerprintType = certificateFingerprintType;
	}

	public PasswordQualityConfig getPasswordQualityConfig() {
		return passwordQualityConfig;
	}

	public void setPasswordQualityConfig(PasswordQualityConfig passwordQualityConfig) {
		this.passwordQualityConfig = passwordQualityConfig;
	}

	public Rectangle getSizeAndPosition() {
		return sizeAndPosition;
	}

	public void setSizeAndPosition(Rectangle sizeAndPosition) {
		this.sizeAndPosition = sizeAndPosition;
	}

	public boolean getShowToolBar() {
		return showToolBar;
	}

	public void setShowToolBar(boolean showToolBar) {
		this.showToolBar = showToolBar;
	}

	public boolean getShowStatusBar() {
		return showStatusBar;
	}

	public void setShowStatusBar(boolean showStatusBar) {
		this.showStatusBar = showStatusBar;
	}

	public int getTabLayout() {
		return tabLayout;
	}

	public void setTabLayout(int tabLayout) {
		this.tabLayout = tabLayout;
	}

	public File[] getRecentFiles() {
		return recentFiles;
	}

	public void setRecentFiles(File[] recentFiles) {
		this.recentFiles = recentFiles;
	}

	public File getCurrentDirectory() {
		return currentDirectory;
	}

	public void setCurrentDirectory(File currentDirectory) {
		this.currentDirectory = currentDirectory;
	}

	public String getLookAndFeelClass() {
		return lookAndFeelClass;
	}

	public void setLookAndFeelClass(String lookAndFeelClass) {
		this.lookAndFeelClass = lookAndFeelClass;
	}

	public boolean getLookAndFeelDecorated() {
		return lookAndFeelDecorated;
	}

	public void setLookAndFeelDecorated(boolean lookAndFeelDecorated) {
		this.lookAndFeelDecorated = lookAndFeelDecorated;
	}

	public boolean getLicenseAgreed() {
		return licenseAgreed;
	}

	public void setLicenseAgreed(boolean licenseAgreed) {
		this.licenseAgreed = licenseAgreed;
	}

	public boolean getShowTipsOnStartUp() {
		return showTipsOnStartUp;
	}

	public void setShowTipsOnStartUp(boolean showTipsOnStartUp) {
		this.showTipsOnStartUp = showTipsOnStartUp;
	}

	public int getNextTipIndex() {
		return nextTipIndex;
	}

	public void setNextTipIndex(int nextTipIndex) {
		this.nextTipIndex = nextTipIndex;
	}
}
