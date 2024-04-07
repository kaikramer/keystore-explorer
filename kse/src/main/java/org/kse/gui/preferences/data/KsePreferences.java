/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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

package org.kse.gui.preferences.data;

import java.awt.Rectangle;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTabbedPane;

import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.PublicKeyFingerprintAlgorithm;
import org.kse.gui.KeyStoreTableColumns;
import org.kse.gui.KseFrame;
import org.kse.gui.password.PasswordQualityConfig;

/**
 * Bean for storing application preferences
 */
public class KsePreferences {

    private CaCertsSettings caCertsSettings = new CaCertsSettings();
    private KeyGenerationSettings keyGenerationDefaults = new KeyGenerationSettings();
    private DigestType certificateFingerprintAlgorithm = DigestType.SHA1;
    private PublicKeyFingerprintAlgorithm publicKeyFingerprintAlgorithm = PublicKeyFingerprintAlgorithm.SKI_METHOD1;
    private PasswordQualityConfig passwordQualityConfig = new PasswordQualityConfig(false, false, 60);
    private ProxySettings proxySettings = new ProxySettings();
    private Rectangle mainWindowSizeAndPosition = new Rectangle(0, 0, KseFrame.DEFAULT_WIDTH, KseFrame.DEFAULT_HEIGHT);
    private boolean showToolBar = true;
    private boolean showStatusBar = true;
    private int tabLayout = JTabbedPane.WRAP_TAB_LAYOUT;
    private List<String> recentFiles = new ArrayList<>();
    private String currentDirectory = null;
    private String lookAndFeelClass = null;
    private boolean lookAndFeelDecorated = false;
    private boolean showTipsOnStartUp = true;
    private int nextTipIndex = 0;
    private String defaultSubjectDN = "";
    private List<String> examineSslHosts = List.of("www.google.com", "www.amazon.com");
    private List<String> examineSslPorts = List.of("443");
    private AutoUpdateCheckSettings autoUpdateCheckSettings = new AutoUpdateCheckSettings();
    private List<String> pkcs11Libraries = new ArrayList<>();
    private String language = LanguageItem.SYSTEM_LANGUAGE;
    private KeyStoreTableColumns keyStoreTableColumns = new KeyStoreTableColumns();
    private int expiryWarnDays = 0;
    private boolean showHiddenFilesEnabled = true;
    private boolean nativeFileChooserEnabled = false;
    private Pkcs12EncryptionSetting pkcs12EncryptionSetting = Pkcs12EncryptionSetting.strong;
    private int serialNumberLengthInBytes = 20;

    // auto-generated getters/setters

    public DigestType getCertificateFingerprintAlgorithm() {
        return certificateFingerprintAlgorithm;
    }

    public void setCertificateFingerprintAlgorithm(DigestType certificateFingerprintAlgorithm) {
        this.certificateFingerprintAlgorithm = certificateFingerprintAlgorithm;
    }

    public PasswordQualityConfig getPasswordQualityConfig() {
        return passwordQualityConfig;
    }

    public void setPasswordQualityConfig(PasswordQualityConfig passwordQualityConfig) {
        this.passwordQualityConfig = passwordQualityConfig;
    }

    public Rectangle getMainWindowSizeAndPosition() {
        return mainWindowSizeAndPosition;
    }

    public void setMainWindowSizeAndPosition(Rectangle mainWindowSizeAndPosition) {
        this.mainWindowSizeAndPosition = mainWindowSizeAndPosition;
    }

    public boolean isShowToolBar() {
        return showToolBar;
    }

    public void setShowToolBar(boolean showToolBar) {
        this.showToolBar = showToolBar;
    }

    public boolean isShowStatusBar() {
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

    public List<String> getRecentFiles() {
        return recentFiles;
    }

    public void setRecentFiles(List<String> recentFiles) {
        this.recentFiles = recentFiles;
    }

    public String getCurrentDirectory() {
        return currentDirectory;
    }

    public void setCurrentDirectory(String currentDirectory) {
        this.currentDirectory = currentDirectory;
    }

    public String getLookAndFeelClass() {
        return lookAndFeelClass;
    }

    public void setLookAndFeelClass(String lookAndFeelClass) {
        this.lookAndFeelClass = lookAndFeelClass;
    }

    public boolean isLookAndFeelDecorated() {
        return lookAndFeelDecorated;
    }

    public void setLookAndFeelDecorated(boolean lookAndFeelDecorated) {
        this.lookAndFeelDecorated = lookAndFeelDecorated;
    }

    public boolean isShowTipsOnStartUp() {
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

    public String getDefaultSubjectDN() {
        return defaultSubjectDN;
    }

    public void setDefaultSubjectDN(String defaultSubjectDN) {
        this.defaultSubjectDN = defaultSubjectDN;
    }

    public List<String> getExamineSslHosts() {
        return examineSslHosts;
    }

    public void setExamineSslHosts(List<String> examineSslHosts) {
        this.examineSslHosts = examineSslHosts;
    }

    public List<String> getExamineSslPorts() {
        return examineSslPorts;
    }

    public void setExamineSslPorts(List<String> examineSslPorts) {
        this.examineSslPorts = examineSslPorts;
    }

    public List<String> getPkcs11Libraries() {
        return pkcs11Libraries;
    }

    public void setPkcs11Libraries(List<String> pkcs11Libraries) {
        this.pkcs11Libraries = pkcs11Libraries;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public KeyStoreTableColumns getKeyStoreTableColumns() {
        return keyStoreTableColumns;
    }

    public void setKeyStoreTableColumns(KeyStoreTableColumns keyStoreTableColumns) {
        this.keyStoreTableColumns = keyStoreTableColumns;
    }

    public int getExpiryWarnDays() {
        return expiryWarnDays;
    }

    public void setExpiryWarnDays(int expiryWarnDays) {
        this.expiryWarnDays = expiryWarnDays;
    }

    public boolean isShowHiddenFilesEnabled() {
        return showHiddenFilesEnabled;
    }

    public void setShowHiddenFilesEnabled(boolean showHiddenFilesEnabled) {
        this.showHiddenFilesEnabled = showHiddenFilesEnabled;
    }

    public Pkcs12EncryptionSetting getPkcs12EncryptionSetting() {
        return pkcs12EncryptionSetting;
    }

    public void setPkcs12EncryptionSetting(Pkcs12EncryptionSetting pkcs12EncryptionSetting) {
        this.pkcs12EncryptionSetting = pkcs12EncryptionSetting;
    }

    public int getSerialNumberLengthInBytes() {
        return serialNumberLengthInBytes;
    }

    public void setSerialNumberLengthInBytes(int serialNumberLengthInBytes) {
        this.serialNumberLengthInBytes = serialNumberLengthInBytes;
    }

    public ProxySettings getProxySettings() {
        return proxySettings;
    }

    public void setProxySettings(ProxySettings proxySettings) {
        this.proxySettings = proxySettings;
    }

    public AutoUpdateCheckSettings getAutoUpdateCheckSettings() {
        return autoUpdateCheckSettings;
    }

    public void setAutoUpdateCheckSettings(AutoUpdateCheckSettings autoUpdateCheckSettings) {
        this.autoUpdateCheckSettings = autoUpdateCheckSettings;
    }

    public CaCertsSettings getCaCertsSettings() {
        return caCertsSettings;
    }

    public void setCaCertsSettings(CaCertsSettings caCertsSettings) {
        this.caCertsSettings = caCertsSettings;
    }

    public KeyGenerationSettings getKeyGenerationDefaults() {
        return keyGenerationDefaults;
    }

    public void setKeyGenerationDefaults(KeyGenerationSettings keyGenerationDefaults) {
        this.keyGenerationDefaults = keyGenerationDefaults;
    }

    public boolean isNativeFileChooserEnabled() {
        return nativeFileChooserEnabled;
    }

    public void setNativeFileChooserEnabled(boolean nativeFileChooserEnabled) {
        this.nativeFileChooserEnabled = nativeFileChooserEnabled;
    }

	public PublicKeyFingerprintAlgorithm getPublicKeyFingerprintAlgorithm() {
		return publicKeyFingerprintAlgorithm;
	}

	public void setPublicKeyFingerprintAlgorithm(PublicKeyFingerprintAlgorithm publicKeyFingerprintAlgorithm) {
		this.publicKeyFingerprintAlgorithm = publicKeyFingerprintAlgorithm;
	}   
}
