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
package org.kse.gui.actions;

import static org.kse.utilities.net.ProxySettingsUpdater.updateSettings;

import java.awt.Toolkit;
import java.io.File;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;
import javax.swing.UIManager;

import org.kse.AuthorityCertificates;
import org.kse.crypto.csr.pkcs12.Pkcs12Util;
import org.kse.gui.KseFrame;
import org.kse.gui.preferences.DPreferences;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.extras.FlatAnimatedLafChange;

/**
 * Action to show preferences.
 */
public class PreferencesAction extends ExitAction {
    private static final long serialVersionUID = 1L;
    private final KseFrame kseFrame;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public PreferencesAction(KseFrame kseFrame) {
        super(kseFrame);
        this.kseFrame = kseFrame;
        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(',',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        putValue(LONG_DESCRIPTION, res.getString("PreferencesAction.statusbar"));
        putValue(NAME, res.getString("PreferencesAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("PreferencesAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/preferences.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        showPreferences();
    }

    /**
     * Display the preferences dialog and store the user's choices.
     */
    public void showPreferences() {
        File caCertificatesFile = new File(preferences.getCaCertsSettings().getCaCertificatesFile());

        DPreferences dPreferences = new DPreferences(frame, preferences);
        dPreferences.setLocationRelativeTo(frame);
        dPreferences.setVisible(true);

        if (dPreferences.wasCancelled()) {
            return;
        }

        File tmpFile = dPreferences.getCaCertificatesFile();

        if (!tmpFile.equals(caCertificatesFile)) {
            AuthorityCertificates authorityCertificates = AuthorityCertificates.getInstance();
            authorityCertificates.setCaCertificates(null);
        }

        caCertificatesFile = tmpFile;

        preferences.getCaCertsSettings().setCaCertificatesFile(caCertificatesFile.getAbsolutePath());
        preferences.getCaCertsSettings().setUseCaCertificates(dPreferences.getUseCaCertificates());
        preferences.getCaCertsSettings().setUseWindowsTrustedRootCertificates(dPreferences.getUseWinTrustRootCertificates());
        preferences.getCaCertsSettings().setImportTrustedCertTrustCheckEnabled(dPreferences.getEnableImportTrustedCertTrustCheck());
        preferences.getCaCertsSettings().setImportCaReplyTrustCheckEnabled(dPreferences.getEnableImportCaReplyTrustCheck());
        preferences.setPasswordQualityConfig(dPreferences.getPasswordQualityConfig());
        preferences.setPasswordGeneratorSettings(dPreferences.getPasswordGeneratorSettings());
        preferences.setDefaultSubjectDN(dPreferences.getDefaultDN());
        preferences.getAutoUpdateCheckSettings().setEnabled(dPreferences.isAutoUpdateChecksEnabled());
        preferences.getAutoUpdateCheckSettings().setCheckInterval(dPreferences.getAutoUpdateChecksInterval());
        preferences.setShowHiddenFilesEnabled(dPreferences.isShowHiddenFilesEnabled());
        preferences.setSerialNumberLengthInBytes(dPreferences.getSerialNumberLengthInBytes());

        preferences.setPkcs12EncryptionSetting(dPreferences.getPkcs12EncryptionSetting());
        Pkcs12Util.setEncryptionStrength(preferences.getPkcs12EncryptionSetting());

        preferences.setLookAndFeelClass(dPreferences.getLookFeelInfo().getClassName());
        preferences.setLookAndFeelDecorated(dPreferences.getLookFeelDecoration());

        String language = dPreferences.getLanguage();
        boolean languageHasChanged = !language.equals(preferences.getLanguage());
        preferences.setLanguage(language);

        if (dPreferences.columnsChanged()) {
            preferences.setKeyStoreTableColumns(dPreferences.getColumns());
            kseFrame.redrawKeyStores(preferences);
        }

        preferences.setExpiryWarnDays(dPreferences.getExpiryWarnDays());

        preferences.setProxySettings(updateSettings(preferences.getProxySettings()));

        preferences.setNativeFileChooserEnabled(dPreferences.isNativeFileChooserEnabled());

        if ((!dPreferences.getLookFeelInfo().getClassName().equals(UIManager.getLookAndFeel().getClass().getName())) ||
            dPreferences.getLookFeelDecoration() != JFrame.isDefaultLookAndFeelDecorated()) {
            FlatAnimatedLafChange.showSnapshot();
            try {
                UIManager.setLookAndFeel(dPreferences.getLookFeelInfo().getClassName());
                JFrame.setDefaultLookAndFeelDecorated(dPreferences.getLookFeelDecoration());
                FlatLaf.updateUI();
            } catch (Exception e) {
                JOptionPane.showMessageDialog(frame, res.getString("PreferencesAction.LookFeelError.message"),
                                              res.getString("PreferencesAction.LookFeelError.Title"), JOptionPane.ERROR_MESSAGE);
            }
            FlatAnimatedLafChange.hideSnapshotWithAnimation();
        }

        if (languageHasChanged) {
            // language changed - restart required for upgrade to take effect
            JOptionPane.showMessageDialog(frame, res.getString("PreferencesAction.LookFeelChanged.message"),
                                          res.getString("PreferencesAction.LookFeelChanged.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);

            exitApplication(true);
        }
    }
}
