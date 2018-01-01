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
package org.kse;

import static org.kse.crypto.digest.DigestType.SHA1;
import static org.kse.crypto.keypair.KeyPairType.RSA;
import static org.kse.crypto.secretkey.SecretKeyType.AES;

import java.awt.Rectangle;
import java.io.File;
import java.io.IOException;
import java.net.ProxySelector;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import javax.swing.JTabbedPane;

import org.kse.crypto.digest.DigestType;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.gui.KseFrame;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.utilities.StringUtils;
import org.kse.utilities.net.ManualProxySelector;
import org.kse.utilities.net.NoProxySelector;
import org.kse.utilities.net.PacProxySelector;
import org.kse.utilities.net.ProxyAddress;
import org.kse.utilities.net.ProxyConfigurationType;
import org.kse.utilities.net.SystemProxySelector;

/**
 * KSE Application settings. Load, save and provide access to the various
 * application settings. Settings persist to Java preferences.
 *
 */
public class ApplicationSettings {

	private static final String PREFS_NODE = "/org/kse";
	private static final String PREFS_NODE_OLD = "/net/sf/keystore_explorer";

	private static final String KSE3_DEFAULTDN = "kse3.defaultdn";
	private static final String KSE3_SSLHOSTS = "kse3.sslhosts";
	private static final String KSE3_SSLPORTS = "kse3.sslports";
	private static final String KSE3_TIPINDEX = "kse3.tipindex";
	private static final String KSE3_TIPSONSTARTUP = "kse3.tipsonstartup";
	private static final String KSE3_LICENSEAGREED = "kse3.licenseagreed";
	private static final String KSE3_LOOKFEEL = "kse3.lookfeel";
	private static final String KSE3_LOOKFEELDECOR = "kse3.lookfeeldecor";
	private static final String KSE3_CURRENTDIR = "kse3.currentdir";
	private static final String KSE3_RECENTFILE = "kse3.recentfile";
	private static final String KSE3_TABLAYOUT = "kse3.tablayout";
	private static final String KSE3_SHOWSTATUSBAR = "kse3.showstatusbar";
	private static final String KSE3_SHOWTOOLBAR = "kse3.showtoolbar";
	private static final String KSE3_WIDTH = "kse3.width";
	private static final String KSE3_HEIGHT = "kse3.height";
	private static final String KSE3_YPOS = "kse3.ypos";
	private static final String KSE3_XPOS = "kse3.xpos";
	private static final String KSE3_PROXY = "kse3.proxy";
	private static final String KSE3_SOCKSPORT = "kse3.socksport";
	private static final String KSE3_SOCKSHOST = "kse3.sockshost";
	private static final String KSE3_HTTPSPORT = "kse3.httpsport";
	private static final String KSE3_HTTPSHOST = "kse3.httpshost";
	private static final String KSE3_HTTPPORT = "kse3.httpport";
	private static final String KSE3_HTTPHOST = "kse3.httphost";
	private static final String KSE3_PACURL = "kse3.pacurl";
	private static final String KSE3_MINPWDQUALENFORCE = "kse3.minpwdqualenforce";
	private static final String KSE3_MINPWDQUAL = "kse3.minpwdqual";
	private static final String KSE3_PWDQUALENABLE = "kse3.pwdqualenable";
	private static final String KSE3_CERTFINGERTYPE = "kse3.certfingertype";
	private static final String KSE3_SECKEYSIZE = "kse3.seckeysize";
	private static final String KSE3_SECKEYTYPE = "kse3.seckeytype";
	private static final String KSE3_KEYPAIRSIZE = "kse3.keypairsize";
	private static final String KSE3_KEYPAIRTYPE = "kse3.keypairtype";
	private static final String KSE3_ENABLEIMPORTCAREPLYTRUSTCHECK = "kse3.enableimportcareplytrustcheck";
	private static final String KSE3_ENABLEIMPORTTRUSTEDCERTTRUSTCHECK = "kse3.enableimporttrustedcerttrustcheck";
	private static final String KSE3_USEWINTRUSTROOTCERTS = "kse3.usewintrustrootcerts";
	private static final String KSE3_CACERTSFILE = "kse3.cacertsfile";
	private static final String KSE3_USECACERTS = "kse3.usecacerts";
	private static final String KSE3_AUTO_UPDATE_CHECK_ENABLED = "kse3.autoupdatecheckenabled";
	private static final String KSE3_AUTO_UPDATE_CHECK_LAST_CHECK = "kse3.autoupdatechecklastcheck";
	private static final String KSE3_AUTO_UPDATE_CHECK_INTERVAL = "kse3.autoupdatecheckinterval";
	private static final String KSE3_PKCS11_LIBS = "kse3.pkcs11libs";

	private static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

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
	private String defaultDN;
	private String sslHosts;
	private String sslPorts;
	private boolean autoUpdateCheckEnabled;
	private Date autoUpdateCheckLastCheck;
	private int autoUpdateCheckInterval;
	private String p11Libs;

	private ApplicationSettings() {

		// one-time conversion from old to new preferences location:
		Preferences root = Preferences.userRoot();
		try {
			// if preferences exist under /net/sf/keystore_explorer but not under /org/kse ...
			if (root.nodeExists(PREFS_NODE_OLD) && !root.nodeExists(PREFS_NODE)) {

				// ... then copy settings from old to new subtree
				Preferences prefsOld = root.node(PREFS_NODE_OLD);
				Preferences prefsNew = root.node(PREFS_NODE);

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
	 * Load application settings from persistent store.
	 */
	public void load() {
		Preferences preferences = getUnderlyingPreferences();

		// Authority certificates
		useCaCertificates = preferences.getBoolean(KSE3_USECACERTS, false);
		String cacertsPath = preferences.get(KSE3_CACERTSFILE,
				AuthorityCertificates.getDefaultCaCertificatesLocation().toString());
		caCertificatesFile = cleanFilePath(new File(cacertsPath));
		useWindowsTrustedRootCertificates = preferences.getBoolean(KSE3_USEWINTRUSTROOTCERTS, false);

		// Trust checks
		enableImportTrustedCertTrustCheck = preferences.getBoolean(KSE3_ENABLEIMPORTTRUSTEDCERTTRUSTCHECK, false);
		enableImportCaReplyTrustCheck = preferences.getBoolean(KSE3_ENABLEIMPORTCAREPLYTRUSTCHECK, false);

		// Key pair generation
		generateKeyPairType = KeyPairType.resolveJce(preferences.get(KSE3_KEYPAIRTYPE, RSA.jce()));
		if (generateKeyPairType == null) {
			generateKeyPairType = RSA;
		}
		int defaultKeyPairSize;
		if (generateKeyPairType == RSA) {
			defaultKeyPairSize = 2048;
		} else {
			defaultKeyPairSize = 1024; // DSA
		}
		generateKeyPairSize = preferences.getInt(KSE3_KEYPAIRSIZE, defaultKeyPairSize);

		// Secret key generation
		generateSecretKeyType = SecretKeyType.resolveJce(preferences.get(KSE3_SECKEYTYPE, AES.jce()));
		if (generateSecretKeyType == null) {
			generateSecretKeyType = AES;
		}
		generateSecretKeySize = preferences.getInt(KSE3_SECKEYSIZE, 192);

		// Certificate fingerprint
		certificateFingerprintType = DigestType.resolveJce(preferences.get(KSE3_CERTFINGERTYPE, SHA1.jce()));
		if (certificateFingerprintType == null) {
			certificateFingerprintType = SHA1;
		}

		// Password quality
		passwordQualityConfig = new PasswordQualityConfig(preferences.getBoolean(KSE3_PWDQUALENABLE, false),
				preferences.getBoolean(KSE3_MINPWDQUALENFORCE, false), preferences.getInt(KSE3_MINPWDQUAL, 60));

		// Internet proxy settings
		ProxyConfigurationType proxyConfigurationType = ProxyConfigurationType.resolve(preferences.get(KSE3_PROXY,
				ProxyConfigurationType.SYSTEM.name()));

		// default should be system settings because of "java.net.useSystemProxies=true", save it for later usage
		SystemProxySelector.setSystemProxySelector(ProxySelector.getDefault());

		switch (proxyConfigurationType) {
		case NONE:
			ProxySelector.setDefault(new NoProxySelector());
			break;
		case PAC:
			// Use PAC URL for proxy configuration
			String pacUrl = preferences.get(KSE3_PACURL, null);
			if (pacUrl != null) {
				ProxySelector.setDefault(new PacProxySelector(pacUrl));
			} else {
				ProxySelector.setDefault(new NoProxySelector());
			}
			break;
		case MANUAL:
			// Use manual settings for HTTP, HTTPS and SOCKS
			ProxyAddress httpProxyAddress = null;
			ProxyAddress httpsProxyAddress = null;
			ProxyAddress socksProxyAddress = null;

			String httpHost = preferences.get(KSE3_HTTPHOST, null);
			int httpPort = preferences.getInt(KSE3_HTTPPORT, 0);

			if (httpHost != null && httpPort > 0) {
				httpProxyAddress = new ProxyAddress(httpHost, httpPort);
			}

			String httpsHost = preferences.get(KSE3_HTTPSHOST, null);
			int httpsPort = preferences.getInt(KSE3_HTTPSPORT, 0);

			if (httpsHost != null && httpsPort > 0) {
				httpsProxyAddress = new ProxyAddress(httpsHost, httpsPort);
			}

			String socksHost = preferences.get(KSE3_SOCKSHOST, null);
			int socksPort = preferences.getInt(KSE3_SOCKSPORT, 0);

			if (socksHost != null && socksPort > 0) {
				socksProxyAddress = new ProxyAddress(socksHost, socksPort);
			}

			if (httpProxyAddress != null || httpsProxyAddress != null) {
				ProxySelector.setDefault(new ManualProxySelector(httpProxyAddress, httpsProxyAddress, null,
						socksProxyAddress));
			} else {
				// no manual settings - use no proxy to connect to the Internet
				ProxySelector.setDefault(new NoProxySelector());
			}
			break;
		case SYSTEM:
		default:
			ProxySelector.setDefault(new SystemProxySelector());
			break;
		}

		// Application size and position
		sizeAndPosition = new Rectangle(preferences.getInt(KSE3_XPOS, 0), preferences.getInt(KSE3_YPOS, 0),
				preferences.getInt(KSE3_WIDTH, KseFrame.DEFAULT_WIDTH), preferences.getInt(KSE3_HEIGHT,
						KseFrame.DEFAULT_HEIGHT));

		// User interface
		showToolBar = preferences.getBoolean(KSE3_SHOWTOOLBAR, true);
		showStatusBar = preferences.getBoolean(KSE3_SHOWSTATUSBAR, true);
		tabLayout = preferences.getInt(KSE3_TABLAYOUT, JTabbedPane.WRAP_TAB_LAYOUT);

		// Recent files
		ArrayList<File> recentFilesList = new ArrayList<File>();
		for (int i = 1; i <= KseFrame.RECENT_FILES_SIZE; i++) {
			String recentFile = preferences.get(KSE3_RECENTFILE + i, null);

			if (recentFile == null) {
				break;
			} else {
				recentFilesList.add(cleanFilePath(new File(recentFile)));
			}
		}
		recentFiles = recentFilesList.toArray(new File[recentFilesList.size()]);

		// Current directory
		String currentDirectoryStr = preferences.get(KSE3_CURRENTDIR, null);
		if (currentDirectoryStr != null) {
			currentDirectory = cleanFilePath(new File(currentDirectoryStr));
		}

		// Look and feel
		lookAndFeelClass = preferences.get(KSE3_LOOKFEEL, null);
		lookAndFeelDecorated = preferences.getBoolean(KSE3_LOOKFEELDECOR, false);

		// Licensing
		licenseAgreed = preferences.getBoolean(KSE3_LICENSEAGREED, false);

		// Tip of the day
		showTipsOnStartUp = preferences.getBoolean(KSE3_TIPSONSTARTUP, true);
		nextTipIndex = preferences.getInt(KSE3_TIPINDEX, 0);

		// Default distinguished name
		defaultDN = preferences.get(KSE3_DEFAULTDN, "");

		// SSL host names and ports for "Examine SSL"
		sslHosts = preferences.get(KSE3_SSLHOSTS, "www.google.com;www.amazon.com");
		sslPorts = preferences.get(KSE3_SSLPORTS, "443");

		// auto update check
		autoUpdateCheckEnabled = preferences.getBoolean(KSE3_AUTO_UPDATE_CHECK_ENABLED, true);
		autoUpdateCheckInterval = preferences.getInt(KSE3_AUTO_UPDATE_CHECK_INTERVAL, 14);
		autoUpdateCheckLastCheck = getDate(preferences, KSE3_AUTO_UPDATE_CHECK_LAST_CHECK, new Date());

		// PKCS#11 libraries
		p11Libs = preferences.get(KSE3_PKCS11_LIBS, "");
	}

	private File cleanFilePath(File filePath) {
		try {
			return filePath.getCanonicalFile();
		} catch (IOException e) {
			return filePath;
		}
	}

	private Date getDate(Preferences preferences, String name,  Date def) {
		try {
			return DATE_FORMAT.parse(preferences.get(name, DATE_FORMAT.format(def)));
		} catch (ParseException e) {
			return def;
		}
	}

	/**
	 * Save application settings to persistent store.
	 */
	public void save() {
		Preferences preferences = getUnderlyingPreferences();

		// Authority certificates
		preferences.putBoolean(KSE3_USECACERTS, useCaCertificates);
		preferences.put(KSE3_CACERTSFILE, caCertificatesFile.toString());
		preferences.putBoolean(KSE3_USEWINTRUSTROOTCERTS, useWindowsTrustedRootCertificates);

		// Trust checks
		preferences.putBoolean(KSE3_ENABLEIMPORTTRUSTEDCERTTRUSTCHECK, enableImportTrustedCertTrustCheck);
		preferences.putBoolean(KSE3_ENABLEIMPORTCAREPLYTRUSTCHECK, enableImportCaReplyTrustCheck);

		// Key pair generation
		preferences.put(KSE3_KEYPAIRTYPE, generateKeyPairType.jce());
		preferences.putInt(KSE3_KEYPAIRSIZE, generateKeyPairSize);

		// Secret key generation
		preferences.put(KSE3_SECKEYTYPE, generateSecretKeyType.jce());
		preferences.putInt(KSE3_SECKEYSIZE, generateSecretKeySize);

		// Certificate fingerprint
		preferences.put(KSE3_CERTFINGERTYPE, certificateFingerprintType.jce());

		// Password quality
		preferences.putBoolean(KSE3_PWDQUALENABLE, passwordQualityConfig.getEnabled());
		preferences.putBoolean(KSE3_MINPWDQUALENFORCE, passwordQualityConfig.getEnforced());
		preferences.putInt(KSE3_MINPWDQUAL, passwordQualityConfig.getMinimumQuality());

		// Internet proxy settings
		getCurrentProxySettings(preferences);

		// Application size and position
		preferences.putInt(KSE3_XPOS, sizeAndPosition.x);
		preferences.putInt(KSE3_YPOS, sizeAndPosition.y);
		preferences.putInt(KSE3_WIDTH, sizeAndPosition.width);
		preferences.putInt(KSE3_HEIGHT, sizeAndPosition.height);

		// User interface
		preferences.putBoolean(KSE3_SHOWTOOLBAR, showToolBar);
		preferences.putBoolean(KSE3_SHOWSTATUSBAR, showStatusBar);
		preferences.putInt(KSE3_TABLAYOUT, tabLayout);

		// Recent files
		clearExistingRecentFiles(preferences);
		for (int i = 1; i <= recentFiles.length; i++) {
			preferences.put(KSE3_RECENTFILE + i, recentFiles[i - 1].toString());
		}

		// Current directory
		preferences.put(KSE3_CURRENTDIR, currentDirectory.toString());

		// Look and feel
		preferences.put(KSE3_LOOKFEEL, lookAndFeelClass);
		preferences.putBoolean(KSE3_LOOKFEELDECOR, lookAndFeelDecorated);

		// Licensing
		preferences.putBoolean(KSE3_LICENSEAGREED, licenseAgreed);

		// Tip of the day
		preferences.putBoolean(KSE3_TIPSONSTARTUP, showTipsOnStartUp);
		preferences.putInt(KSE3_TIPINDEX, nextTipIndex);

		// Default distinguished name
		preferences.put(KSE3_DEFAULTDN, defaultDN);

		// SSL host names and ports for "Examine SSL"
		preferences.put(KSE3_SSLHOSTS, getSslHosts());
		preferences.put(KSE3_SSLPORTS, getSslPorts());

		// auto update check settings
		preferences.putBoolean(KSE3_AUTO_UPDATE_CHECK_ENABLED, isAutoUpdateCheckEnabled());
		preferences.putInt(KSE3_AUTO_UPDATE_CHECK_INTERVAL, getAutoUpdateCheckInterval());
		preferences.put(KSE3_AUTO_UPDATE_CHECK_LAST_CHECK, DATE_FORMAT.format(getAutoUpdateCheckLastCheck()));

		// PKCS#11 libraries
		preferences.put(KSE3_PKCS11_LIBS, getP11Libs());
	}

	private void clearExistingRecentFiles(Preferences preferences) {
		// Clear all existing recent files (new list may be shorter than the existing one)
		for (int i = 1; i <= KseFrame.RECENT_FILES_SIZE; i++) {
			String recentFile = preferences.get(KSE3_RECENTFILE + i, null);

			if (recentFile == null) {
				break;
			} else {
				preferences.remove(KSE3_RECENTFILE + i);
			}
		}
	}

	private void getCurrentProxySettings(Preferences preferences) {
		// Get current proxy settings
		ProxySelector proxySelector = ProxySelector.getDefault();

		if (proxySelector instanceof NoProxySelector) {
			preferences.put(KSE3_PROXY, ProxyConfigurationType.NONE.name());
		} else if (proxySelector instanceof SystemProxySelector) {
			preferences.put(KSE3_PROXY, ProxyConfigurationType.SYSTEM.name());
		}else if (proxySelector instanceof PacProxySelector) {
			PacProxySelector pacProxySelector = (PacProxySelector) proxySelector;

			preferences.put(KSE3_PACURL, pacProxySelector.getPacUrl());
			preferences.put(KSE3_PROXY, ProxyConfigurationType.PAC.name());
		} else if (proxySelector instanceof ManualProxySelector) {
			ManualProxySelector manualProxySelector = (ManualProxySelector) proxySelector;

			ProxyAddress httpProxyAddress = manualProxySelector.getHttpProxyAddress();
			if (httpProxyAddress != null) {
				preferences.put(KSE3_HTTPHOST, httpProxyAddress.getHost());
				preferences.putInt(KSE3_HTTPPORT, httpProxyAddress.getPort());
			}

			ProxyAddress httpsProxyAddress = manualProxySelector.getHttpsProxyAddress();
			if (httpsProxyAddress != null) {
				preferences.put(KSE3_HTTPSHOST, httpsProxyAddress.getHost());
				preferences.putInt(KSE3_HTTPSPORT, httpsProxyAddress.getPort());
			}

			ProxyAddress socksProxyAddress = manualProxySelector.getSocksProxyAddress();
			if (socksProxyAddress != null) {
				preferences.put(KSE3_SOCKSHOST, socksProxyAddress.getHost());
				preferences.putInt(KSE3_SOCKSPORT, socksProxyAddress.getPort());
			}

			preferences.put(KSE3_PROXY, ProxyConfigurationType.MANUAL.name());
		}
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
		Preferences preferences = Preferences.userRoot().node(PREFS_NODE);
		return preferences;
	}

	/**
	 * Add a new SSL port to start of current list of ports.
	 *
	 * Maximum number is 10. If port is already in list, it is brought to the first position.
	 *
	 * @param newSslPort New SSL port
	 */
	public void addSslPort(String newSslPort) {

		String newSslPorts = StringUtils.addToList(newSslPort, getSslPorts(), 10);

		setSslPorts(newSslPorts);
	}


	/**
	 * Add a new SSL host to start of current list of hosts.
	 *
	 * Maximum number is 10. If host is already in list, it is brought to the first position.
	 *
	 * @param newSslHost New SSL host
	 */
	public void addSslHost(String newSslHost) {

		String newSslHosts = StringUtils.addToList(newSslHost, getSslHosts(), 10);

		setSslHosts(newSslHosts);
	}

	/**
	 * Add a new PKCS#11 library path host to start of current list of libraries.
	 *
	 * Maximum number is 10. If host is already in list, it is brought to the first position.
	 *
	 * @param newSslHost New SSL host
	 */
	public void addP11Lib(String p11Lib) {

		String newP11Libs = StringUtils.addToList(p11Lib, getP11Libs(), 10);

		setP11Libs(newP11Libs);
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

	public String getDefaultDN() {
		return defaultDN;
	}

	public void setDefaultDN(String defaultDN) {
		this.defaultDN = defaultDN;
	}

	public String getSslHosts() {
		return sslHosts;
	}

	public void setSslHosts(String sslHosts) {
		this.sslHosts = sslHosts;
	}

	public String getSslPorts() {
		return sslPorts;
	}

	public void setSslPorts(String sslPorts) {
		this.sslPorts = sslPorts;
	}

	public boolean isAutoUpdateCheckEnabled() {
		return autoUpdateCheckEnabled;
	}

	public void setAutoUpdateCheckEnabled(boolean autoUpdateCheckEnabled) {
		this.autoUpdateCheckEnabled = autoUpdateCheckEnabled;
	}

	public Date getAutoUpdateCheckLastCheck() {
		return autoUpdateCheckLastCheck;
	}

	public void setAutoUpdateCheckLastCheck(Date autoUpdateCheckLastCheck) {
		this.autoUpdateCheckLastCheck = autoUpdateCheckLastCheck;
	}

	public int getAutoUpdateCheckInterval() {
		return autoUpdateCheckInterval;
	}

	public void setAutoUpdateCheckInterval(int autoUpdateCheckInterval) {
		this.autoUpdateCheckInterval = autoUpdateCheckInterval;
	}

	public String getP11Libs() {
		return p11Libs;
	}

	public void setP11Libs(String p11Libs) {
		this.p11Libs = p11Libs;
	}
}
