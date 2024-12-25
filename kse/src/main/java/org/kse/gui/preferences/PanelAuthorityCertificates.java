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
package org.kse.gui.preferences;

import java.io.File;
import java.security.Security;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.kse.crypto.SecurityProvider;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.PlatformUtil;
import org.kse.gui.preferences.data.CaCertsSettings;
import org.kse.gui.preferences.data.KsePreferences;

import net.miginfocom.swing.MigLayout;

class PanelAuthorityCertificates {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");

    private final DPreferences parent;
    private final KsePreferences preferences;

    private JTextField jtfCaCertificatesFile;
    private JCheckBox jcbUseCaCertificates;
    private JCheckBox jcbUseWinTrustedRootCertificates;
    private JCheckBox jcbEnableImportTrustedCertTrustCheck;
    private JCheckBox jcbEnableImportCaReplyTrustCheck;

    PanelAuthorityCertificates(DPreferences parent, KsePreferences preferences) {
        this.parent = parent;
        this.preferences = preferences;
    }

    JPanel initAuthorityCertificatesCard() {
        CaCertsSettings caCertsSettings = preferences.getCaCertsSettings();

        JLabel jlCaCertificatesFile = new JLabel(res.getString("DPreferences.jlCaCertificatesFile.text"));

        jtfCaCertificatesFile = new JTextField(caCertsSettings.getCaCertificatesFile(), 25);
        jtfCaCertificatesFile.setToolTipText(res.getString("DPreferences.jtfCaCertificatesFile.tooltip"));
        jtfCaCertificatesFile.setCaretPosition(0);
        jtfCaCertificatesFile.setEditable(false);

        JButton jbBrowseCaCertificatesFile = new JButton(res.getString("DPreferences.jbBrowseCaCertificatesFile.text"));
        PlatformUtil.setMnemonic(jbBrowseCaCertificatesFile,
                                 res.getString("DPreferences.jbBrowseCaCertificatesFile.mnemonic").charAt(0));
        jbBrowseCaCertificatesFile.setToolTipText(res.getString("DPreferences.jbBrowseCaCertificatesFile.tooltip"));

        jcbUseCaCertificates = new JCheckBox(res.getString("DPreferences.jcbUseCaCertificates.text"),
                                             caCertsSettings.isUseCaCertificates());
        jcbUseCaCertificates.setToolTipText(res.getString("DPreferences.jcbUseCaCertificates.tooltip"));
        PlatformUtil.setMnemonic(jcbUseCaCertificates,
                                 res.getString("DPreferences.jcbUseCaCertificates.mnemonic").charAt(0));

        jcbUseWinTrustedRootCertificates =
                new JCheckBox(res.getString("DPreferences.jcbUseWinTrustRootCertificates.text"),
                              caCertsSettings.isUseWindowsTrustedRootCertificates());
        jcbUseWinTrustedRootCertificates
                .setToolTipText(res.getString("DPreferences.jcbUseWinTrustRootCertificates.tooltip"));
        PlatformUtil.setMnemonic(jcbUseWinTrustedRootCertificates,
                                 res.getString("DPreferences.jcbUseWinTrustRootCertificates.menmonic").charAt(0));

        JLabel jlTrustChecks = new JLabel(res.getString("DPreferences.jlTrustChecks.text"));

        jcbEnableImportTrustedCertTrustCheck = new JCheckBox(
                res.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.text"),
                caCertsSettings.isImportTrustedCertTrustCheckEnabled());
        jcbEnableImportTrustedCertTrustCheck
                .setToolTipText(res.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.tooltip"));
        jcbEnableImportTrustedCertTrustCheck
                .setMnemonic(res.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.mnemonic").charAt(0));

        jcbEnableImportCaReplyTrustCheck =
                new JCheckBox(res.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.text"),
                              caCertsSettings.isImportCaReplyTrustCheckEnabled());
        jcbEnableImportCaReplyTrustCheck
                .setToolTipText(res.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.tooltip"));
        jcbEnableImportCaReplyTrustCheck
                .setMnemonic(res.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.mnemonic").charAt(0));

        // layout
        JPanel jpAuthorityCertificates = new JPanel();
        jpAuthorityCertificates.setLayout(new MigLayout("insets dialog", "20lp[][]", "20lp[][]"));

        jpAuthorityCertificates.add(jlCaCertificatesFile, "split");
        jpAuthorityCertificates.add(jtfCaCertificatesFile, "");
        jpAuthorityCertificates.add(jbBrowseCaCertificatesFile, "wrap rel");
        if (Security.getProvider(SecurityProvider.MS_CAPI.jce()) != null) {
            jpAuthorityCertificates.add(jcbUseCaCertificates, "wrap rel");
            jpAuthorityCertificates.add(jcbUseWinTrustedRootCertificates, "wrap para");
        } else {
            jpAuthorityCertificates.add(jcbUseCaCertificates, "wrap para");
        }
        jpAuthorityCertificates.add(jlTrustChecks, "wrap unrel");
        jpAuthorityCertificates.add(jcbEnableImportTrustedCertTrustCheck, "wrap rel");
        jpAuthorityCertificates.add(jcbEnableImportCaReplyTrustCheck, "wrap unrel");

        jbBrowseCaCertificatesFile.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(parent);
                browsePressed();
            } finally {
                CursorUtil.setCursorFree(parent);
            }
        });

        return jpAuthorityCertificates;
    }

    private void browsePressed() {
        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();
        File caCertsFile = new File(preferences.getCaCertsSettings().getCaCertificatesFile());

        if ((caCertsFile.getParentFile() != null) && (caCertsFile.getParentFile().exists())) {
            chooser.setCurrentDirectory(caCertsFile.getParentFile());
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DPreferences.ChooseCACertificatesKeyStore.Title"));
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("DPreferences.CaCertificatesKeyStoreFileChooser.button"));

        int rtnValue = chooser.showOpenDialog(parent);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfCaCertificatesFile.setText(chosenFile.toString());
            jtfCaCertificatesFile.setCaretPosition(0);
        }
    }

    JTextField getJtfCaCertificatesFile() {
        return jtfCaCertificatesFile;
    }

    JCheckBox getJcbUseCaCertificates() {
        return jcbUseCaCertificates;
    }

    JCheckBox getJcbUseWinTrustedRootCertificates() {
        return jcbUseWinTrustedRootCertificates;
    }

    JCheckBox getJcbEnableImportTrustedCertTrustCheck() {
        return jcbEnableImportTrustedCertTrustCheck;
    }

    JCheckBox getJcbEnableImportCaReplyTrustCheck() {
        return jcbEnableImportCaReplyTrustCheck;
    }
}
