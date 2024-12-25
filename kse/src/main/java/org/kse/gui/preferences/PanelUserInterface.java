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

import java.util.ArrayList;
import java.util.ResourceBundle;
import java.util.TreeSet;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSlider;
import javax.swing.JSpinner;
import javax.swing.LookAndFeel;
import javax.swing.SpinnerNumberModel;
import javax.swing.UIManager;

import org.kse.gui.MiGUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.preferences.data.AutoUpdateCheckSettings;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.gui.preferences.data.LanguageItem;
import org.kse.gui.preferences.data.Pkcs12EncryptionSetting;

import net.miginfocom.swing.MigLayout;

class PanelUserInterface {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");

    private final DPreferences parent;
    private final KsePreferences preferences;

    private final ArrayList<UIManager.LookAndFeelInfo> lookFeelInfoList = new ArrayList<>();

    private JCheckBox jcbEnablePasswordQuality;
    private JCheckBox jcbEnforceMinimumPasswordQuality;
    private JLabel jlMinimumPasswordQuality;
    private JSlider jsMinimumPasswordQuality;
    private JComboBox<String> jcbLookFeel;
    private JComboBox<LanguageItem> jcbLanguage;
    private JCheckBox jcbShowHiddenFiles;
    private JCheckBox jcbShowNativeFileChooser;
    private JCheckBox jcbLookFeelDecorated;
    private JComboBox<Pkcs12EncryptionSetting> jcbPkcs12Encryption;
    private JSpinner jspSnRandomBytes;

    private JCheckBox jcbEnableAutoUpdateChecks;
    private JSpinner jspAutoUpdateCheckInterval;

    PanelUserInterface(DPreferences parent, KsePreferences preferences) {
        this.parent = parent;
        this.preferences = preferences;
    }


    JPanel initUserInterfaceCard() {
        JLabel jlLookFeel = new JLabel(res.getString("DPreferences.jlLookFeel.text"));

        jcbLookFeel = new JComboBox<>();
        jcbLookFeel.setToolTipText(res.getString("DPreferences.jcbLookFeel.tooltip"));

        initLookAndFeelSelection();

        jcbLookFeelDecorated = new JCheckBox(res.getString("DPreferences.jcbLookFeelDecorated.text"),
                                             JFrame.isDefaultLookAndFeelDecorated());
        jcbLookFeelDecorated.setToolTipText(res.getString("DPreferences.jcbLookFeelDecorated.tooltip"));
        PlatformUtil.setMnemonic(jcbLookFeelDecorated,
                                 res.getString("DPreferences.jcbLookFeelDecorated.menmonic").charAt(0));

        JLabel jlLanguage = new JLabel(res.getString("DPreferences.jlLanguage.text"));

        jcbLanguage = new JComboBox<>();
        jcbLanguage.setToolTipText(res.getString("DPreferences.jcbLanguage.tooltip"));
        initLanguageSelection();

        JLabel jlAutoUpdateChecks = new JLabel(res.getString("DPreferences.jlAutoUpdateChecks.text"));
        jcbEnableAutoUpdateChecks = new JCheckBox(res.getString("DPreferences.jcbEnableAutoUpdateChecks.text"));
        AutoUpdateCheckSettings autoUpdateCheckSettings = preferences.getAutoUpdateCheckSettings();
        jcbEnableAutoUpdateChecks.setSelected(autoUpdateCheckSettings.isEnabled());
        var spinnerModel = new SpinnerNumberModel(autoUpdateCheckSettings.getCheckInterval(), 1.0, 999.0, 1.0);
        jspAutoUpdateCheckInterval = new JSpinner(spinnerModel);
        jspAutoUpdateCheckInterval.setEnabled(autoUpdateCheckSettings.isEnabled());
        JLabel jlAutoUpdateChecksDays = new JLabel(res.getString("DPreferences.jlAutoUpdateChecksDays.text"));

        JLabel jlPasswordQuality = new JLabel(res.getString("DPreferences.jpPasswordQuality.text"));

        jcbEnablePasswordQuality = new JCheckBox(res.getString("DPreferences.jcbEnablePasswordQuality.text"));
        jcbEnablePasswordQuality.setMnemonic(res.getString("DPreferences.jcbEnablePasswordQuality.mnemonic").charAt(0));
        jcbEnablePasswordQuality.setToolTipText(res.getString("DPreferences.jcbEnablePasswordQuality.tooltip"));

        jcbEnforceMinimumPasswordQuality = new JCheckBox(
                res.getString("DPreferences.jcbEnforceMinimumPasswordQuality.text"));
        jcbEnforceMinimumPasswordQuality
                .setMnemonic(res.getString("DPreferences.jcbEnforceMinimumPasswordQuality.mnemonic").charAt(0));
        jcbEnforceMinimumPasswordQuality
                .setToolTipText(res.getString("DPreferences.jcbEnforceMinimumPasswordQuality.tooltip"));

        jlMinimumPasswordQuality = new JLabel(res.getString("DPreferences.jlMinimumPasswordQuality.text"));

        jsMinimumPasswordQuality = new JSlider(0, 100);
        jsMinimumPasswordQuality.setPaintLabels(true);
        jsMinimumPasswordQuality.setMajorTickSpacing(25);
        jsMinimumPasswordQuality.setToolTipText(res.getString("DPreferences.jsMinimumPasswordQuality.tooltip"));

        boolean passwordQualityEnabled = preferences.getPasswordQualityConfig().getEnabled();
        boolean passwordQualityEnforced = preferences.getPasswordQualityConfig().getEnforced();
        int minimumPasswordQuality = preferences.getPasswordQualityConfig().getMinimumQuality();

        jcbEnablePasswordQuality.setSelected(passwordQualityEnabled);
        jcbEnforceMinimumPasswordQuality.setSelected(passwordQualityEnforced);
        jsMinimumPasswordQuality.setValue(minimumPasswordQuality);

        jcbEnforceMinimumPasswordQuality.setEnabled(passwordQualityEnabled);

        jlMinimumPasswordQuality.setEnabled(passwordQualityEnabled && passwordQualityEnforced);
        jsMinimumPasswordQuality.setEnabled(passwordQualityEnabled && passwordQualityEnforced);

        JLabel jlFileChooser = new JLabel(res.getString("DPreferences.jlFileChooser.text"));

        jcbShowHiddenFiles = new JCheckBox(res.getString("DPreferences.jcbShowHiddenFiles.text"));
        jcbShowHiddenFiles.setSelected(preferences.isShowHiddenFilesEnabled());

        jcbShowNativeFileChooser = new JCheckBox(res.getString("DPreferences.jcbShowNativeFileChooser.text"));
        jcbShowNativeFileChooser.setSelected(preferences.isNativeFileChooserEnabled());

        JLabel jlPkcs12Encryption  = new JLabel(res.getString("DPreferences.jlPkcs12Encryption.text"));
        Pkcs12EncryptionSetting.setResourceBundle(res);
        jcbPkcs12Encryption = new JComboBox<>(Pkcs12EncryptionSetting.values());
        jcbPkcs12Encryption.setSelectedItem(preferences.getPkcs12EncryptionSetting());
        jcbPkcs12Encryption.setToolTipText(res.getString("DPreferences.jcbPkcs12Encryption.tooltip"));

        JLabel jlSnRandomBytes = new JLabel(res.getString("DPreferences.jlSnRandomBytes.text"));
        var snSpinnerModel = new SpinnerNumberModel(preferences.getSerialNumberLengthInBytes(), 8.0, 20.0, 1.0);
        jspSnRandomBytes = new JSpinner(snSpinnerModel);
        JSpinner.DefaultEditor editor = ( JSpinner.DefaultEditor ) jspSnRandomBytes.getEditor();
        editor.getTextField().setEnabled(true);
        editor.getTextField().setEditable(false);
        jspSnRandomBytes.setToolTipText(res.getString("DPreferences.jlSnRandomBytes.tooltip"));
        JLabel jlSnRandomBytesPostfix = new JLabel(res.getString("DPreferences.jlSnRandomBytesPostfix.text"));

        // layout
        JPanel jpUI = new JPanel();
        jpUI.setLayout(new MigLayout("insets dialog", "20lp[][]", "20lp[][]"));
        MiGUtil.addSeparator(jpUI, jlLookFeel.getText());
        jpUI.add(jcbLookFeel, "gapx indent, wrap");
        jpUI.add(jcbLookFeelDecorated, "gapx indent, wrap");
        MiGUtil.addSeparator(jpUI, jlLanguage.getText());
        jpUI.add(jcbLanguage, "gapx indent, wrap unrel");
        MiGUtil.addSeparator(jpUI, jlAutoUpdateChecks.getText());
        jpUI.add(jcbEnableAutoUpdateChecks, "gapx indent");
        jpUI.add(jspAutoUpdateCheckInterval, "");
        jpUI.add(jlAutoUpdateChecksDays, "wrap unrel");
        MiGUtil.addSeparator(jpUI, jlPasswordQuality.getText());
        jpUI.add(jcbEnablePasswordQuality, "gapx indent, spanx, wrap");
        jpUI.add(jcbEnforceMinimumPasswordQuality, "spanx, gapx 2*indent, wrap");
        jpUI.add(jlMinimumPasswordQuality, "gapx 4*indent, top, spanx, split 3");
        jpUI.add(jsMinimumPasswordQuality, "wrap");
        MiGUtil.addSeparator(jpUI, jlFileChooser.getText());
        jpUI.add(jcbShowHiddenFiles, "spanx, gapx indent, wrap rel");
        jpUI.add(jcbShowNativeFileChooser, "spanx, gapx indent, wrap unrel");
        MiGUtil.addSeparator(jpUI, jlPkcs12Encryption.getText());
        jpUI.add(jcbPkcs12Encryption, "gapx indent, spanx, wrap unrel");
        MiGUtil.addSeparator(jpUI, jlSnRandomBytes.getText());
        jpUI.add(jspSnRandomBytes, "gapx indent, split 2");
        jpUI.add(jlSnRandomBytesPostfix, "");

        jcbEnableAutoUpdateChecks
                .addItemListener(evt -> jspAutoUpdateCheckInterval.setEnabled(jcbEnableAutoUpdateChecks.isSelected()));

        jcbEnablePasswordQuality.addItemListener(evt -> {
            jcbEnforceMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected());
            jlMinimumPasswordQuality
                    .setEnabled(jcbEnablePasswordQuality.isSelected() && jcbEnforceMinimumPasswordQuality.isSelected());
            jsMinimumPasswordQuality
                    .setEnabled(jcbEnablePasswordQuality.isSelected() && jcbEnforceMinimumPasswordQuality.isSelected());
        });

        jcbEnforceMinimumPasswordQuality.addItemListener(evt -> {
            jlMinimumPasswordQuality
                    .setEnabled(jcbEnablePasswordQuality.isSelected() && jcbEnforceMinimumPasswordQuality.isSelected());
            jsMinimumPasswordQuality
                    .setEnabled(jcbEnablePasswordQuality.isSelected() && jcbEnforceMinimumPasswordQuality.isSelected());
        });

        return jpUI;
    }

    private void initLookAndFeelSelection() {
        // This may contain duplicates
        UIManager.LookAndFeelInfo[] lookFeelInfos = UIManager.getInstalledLookAndFeels();
        LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();
        TreeSet<String> lookFeelClasses = new TreeSet<>();

        for (UIManager.LookAndFeelInfo lfi : lookFeelInfos) {
            // Avoid duplicates
            if (!lookFeelClasses.contains(lfi.getClassName())) {
                lookFeelClasses.add(lfi.getClassName());

                lookFeelInfoList.add(lfi);
                jcbLookFeel.addItem(lfi.getName());

                // Pre-select current look & feel - compare by class as the look
                // and feel name can differ from the look and feel info name
                if ((currentLookAndFeel != null)
                    && (currentLookAndFeel.getClass().getName().equals(lfi.getClassName()))) {
                    jcbLookFeel.setSelectedIndex(jcbLookFeel.getItemCount() - 1);
                }
            }
        }
    }

    private void initLanguageSelection() {
        LanguageItem[] languageItems = new LanguageItem[] {
                new LanguageItem("System", LanguageItem.SYSTEM_LANGUAGE),
                new LanguageItem("English", "en"),
                new LanguageItem("German", "de"),
                new LanguageItem("French", "fr"),
                new LanguageItem("Russian", "ru"),
                new LanguageItem("Spanish", "es"),
                };

        for (LanguageItem languageItem : languageItems) {
            jcbLanguage.addItem(languageItem);
            if (languageItem.getIsoCode().equals(preferences.getLanguage())) {
                jcbLanguage.setSelectedItem(languageItem);
            }
        }
    }

    UIManager.LookAndFeelInfo getLookFeelInfo() {
        int selectedIndex = jcbLookFeel.getSelectedIndex();
        return lookFeelInfoList.get(selectedIndex);
    }

    String getLanguage() {
        return ((LanguageItem) jcbLanguage.getSelectedItem()).getIsoCode();
    }

    JCheckBox getJcbEnablePasswordQuality() {
        return jcbEnablePasswordQuality;
    }

    JCheckBox getJcbEnforceMinimumPasswordQuality() {
        return jcbEnforceMinimumPasswordQuality;
    }

    JSlider getJsMinimumPasswordQuality() {
        return jsMinimumPasswordQuality;
    }

    JCheckBox getJcbShowHiddenFiles() {
        return jcbShowHiddenFiles;
    }

    JCheckBox getJcbShowNativeFileChooser() {
        return jcbShowNativeFileChooser;
    }

    JCheckBox getJcbLookFeelDecorated() {
        return jcbLookFeelDecorated;
    }

    JComboBox<Pkcs12EncryptionSetting> getJcbPkcs12Encryption() {
        return jcbPkcs12Encryption;
    }

    JSpinner getJspSnRandomBytes() {
        return jspSnRandomBytes;
    }

    JCheckBox getJcbEnableAutoUpdateChecks() {
        return jcbEnableAutoUpdateChecks;
    }

    JSpinner getJspAutoUpdateCheckInterval() {
        return jspAutoUpdateCheckInterval;
    }
}
