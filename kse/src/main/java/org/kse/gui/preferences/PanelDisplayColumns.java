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

import java.util.ResourceBundle;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;

import org.kse.gui.KeyStoreTableColumns;
import org.kse.gui.preferences.data.KsePreferences;

import net.miginfocom.swing.MigLayout;

class PanelDisplayColumns {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");

    private final DPreferences parent;
    private final KsePreferences preferences;

    private JCheckBox jcbEnableEntryName;
    private JCheckBox jcbEnableAlgorithm;
    private JCheckBox jcbEnableKeySize;
    private JCheckBox jcbEnableCertificateValidityStart;
    private JCheckBox jcbEnableCertificateExpiry;
    private JCheckBox jcbEnableLastModified;
    private JCheckBox jcbEnableCurve;
    private JCheckBox jcbEnableSKI;
    private JCheckBox jcbEnableAKI;
    private JCheckBox jcbEnableIssuerDN;
    private JCheckBox jcbEnableIssuerCN;
    private JCheckBox jcbEnableSubjectDN;
    private JCheckBox jcbEnableSubjectCN;
    private JCheckBox jcbEnableIssuerO;
    private JCheckBox jcbEnableSubjectO;
    private JCheckBox jcbEnableSerialNumberHex;
    private JCheckBox jcbEnableSerialNumberDec;
    private JSpinner jspExpirationWarnDays;

    PanelDisplayColumns(DPreferences parent, KsePreferences preferences) {
        this.parent = parent;
        this.preferences = preferences;
    }

    JPanel initDisplayColumnsCard() {
        KeyStoreTableColumns kstColumns = preferences.getKeyStoreTableColumns();

        boolean bEnableEntryName = kstColumns.getEnableEntryName();
        jcbEnableEntryName = new JCheckBox(res.getString("DPreferences.jcbEnableEntryName.text"), bEnableEntryName);
        // fix for problem that without entry name a lot of things do not work
        jcbEnableEntryName.setSelected(true);
        jcbEnableEntryName.setEnabled(false);

        boolean bEnableAlgorithm = kstColumns.getEnableAlgorithm();
        jcbEnableAlgorithm = new JCheckBox(res.getString("DPreferences.jcbEnableAlgorithm.text"), bEnableAlgorithm);

        boolean bEnableKeySize = kstColumns.getEnableKeySize();
        jcbEnableKeySize = new JCheckBox(res.getString("DPreferences.jcbEnableKeySize.text"), bEnableKeySize);
        jcbEnableKeySize.setSelected(bEnableKeySize);

        boolean bEnableCurve = kstColumns.getEnableCurve();
        jcbEnableCurve = new JCheckBox(res.getString("DPreferences.jcbEnableCurve.text"), bEnableCurve);
        jcbEnableCurve.setSelected(bEnableCurve);

        boolean bEnableCertificateValidityStart = kstColumns.getEnableCertificateValidityStart();
        jcbEnableCertificateValidityStart = new JCheckBox(res.getString(
                "DPreferences.jcbEnableCertificateValidityStart.text"), bEnableCertificateValidityStart);
        jcbEnableCertificateValidityStart.setSelected(bEnableCertificateValidityStart);

        boolean bEnableCertificateExpiry = kstColumns.getEnableCertificateExpiry();
        jcbEnableCertificateExpiry = new JCheckBox(res.getString("DPreferences.jcbEnableCertificateExpiry.text"),
                                                   bEnableCertificateExpiry);
        jcbEnableCertificateExpiry.setSelected(bEnableCertificateExpiry);

        boolean bEnableLastModified = kstColumns.getEnableLastModified();
        jcbEnableLastModified = new JCheckBox(res.getString("DPreferences.jcbEnableLastModified.text"),
                                              bEnableLastModified);
        jcbEnableLastModified.setSelected(bEnableLastModified);

        boolean bEnableSKI = kstColumns.getEnableSKI();
        jcbEnableSKI = new JCheckBox(res.getString("DPreferences.jcbEnableSKI.text"), bEnableSKI);
        jcbEnableSKI.setSelected(bEnableSKI);

        boolean bEnableAKI = kstColumns.getEnableAKI();
        jcbEnableAKI = new JCheckBox(res.getString("DPreferences.jcbEnableAKI.text"), bEnableAKI);
        jcbEnableAKI.setSelected(bEnableAKI);

        boolean bEnableIssuerDN = kstColumns.getEnableIssuerDN();
        jcbEnableIssuerDN = new JCheckBox(res.getString("DPreferences.jcbEnableIssuerDN.text"), bEnableIssuerDN);
        jcbEnableIssuerDN.setSelected(bEnableIssuerDN);

        boolean bEnableSubjectDN = kstColumns.getEnableSubjectDN();
        jcbEnableSubjectDN = new JCheckBox(res.getString("DPreferences.jcbEnableSubjectDN.text"), bEnableSubjectDN);
        jcbEnableSubjectDN.setSelected(bEnableSubjectDN);

        boolean bEnableIssuerCN = kstColumns.getEnableIssuerCN();
        jcbEnableIssuerCN = new JCheckBox(res.getString("DPreferences.jcbEnableIssuerCN.text"), bEnableIssuerCN);
        jcbEnableIssuerCN.setSelected(bEnableIssuerCN);

        boolean bEnableSubjectCN = kstColumns.getEnableSubjectCN();
        jcbEnableSubjectCN = new JCheckBox(res.getString("DPreferences.jcbEnableSubjectCN.text"), bEnableSubjectCN);
        jcbEnableSubjectCN.setSelected(bEnableSubjectCN);

        boolean bEnableIssuerO = kstColumns.getEnableIssuerO();
        jcbEnableIssuerO = new JCheckBox(res.getString("DPreferences.jcbEnableIssuerO.text"), bEnableIssuerO);
        jcbEnableIssuerO.setSelected(bEnableIssuerO);

        boolean bEnableSubjectO = kstColumns.getEnableSubjectO();
        jcbEnableSubjectO = new JCheckBox(res.getString("DPreferences.jcbEnableSubjectO.text"), bEnableSubjectO);
        jcbEnableSubjectO.setSelected(bEnableSubjectO);

        boolean bEnableSerialNumberHex = kstColumns.getEnableSerialNumberHex();
        jcbEnableSerialNumberHex = new JCheckBox(res.getString("DPreferences.jcbEnableSerialNumberHex.text"),
                                                 bEnableSerialNumberHex);
        jcbEnableSerialNumberHex.setSelected(bEnableSerialNumberHex);

        boolean bEnableSerialNumberDec = kstColumns.getEnableSerialNumberDec();
        jcbEnableSerialNumberDec = new JCheckBox(res.getString("DPreferences.jcbEnableSerialNumberDec.text"),
                                                 bEnableSerialNumberDec);
        jcbEnableSerialNumberDec.setSelected(bEnableSerialNumberDec);

        JLabel jlExpirationWarnDays = new JLabel(res.getString("DPreferences.jlExpiryWarning.text"));
        var spinnerNumberModel = new SpinnerNumberModel(preferences.getExpiryWarnDays(), 0, 90, 1);
        jspExpirationWarnDays = new JSpinner(spinnerNumberModel);
        JSpinner.DefaultEditor editor = ( JSpinner.DefaultEditor ) jspExpirationWarnDays.getEditor();
        editor.getTextField().setEnabled(true);
        editor.getTextField().setEditable(false);

        // layout
        JPanel jpDisplayColumns = new JPanel();
        jpDisplayColumns.setLayout(new MigLayout("insets dialog", "20lp[]20lp[]", "20lp[]rel[]"));
        jpDisplayColumns.add(jcbEnableEntryName, "left");
        jpDisplayColumns.add(jcbEnableAlgorithm, "left, wrap");
        jpDisplayColumns.add(jcbEnableKeySize, "left");
        jpDisplayColumns.add(jcbEnableCurve, "left, wrap");
        jpDisplayColumns.add(jcbEnableCertificateValidityStart, "left");
        jpDisplayColumns.add(jcbEnableCertificateExpiry, "left, wrap");
        jpDisplayColumns.add(jcbEnableLastModified, "left");
        jpDisplayColumns.add(jcbEnableSKI, "left, wrap");
        jpDisplayColumns.add(jcbEnableAKI, "left");
        jpDisplayColumns.add(jcbEnableIssuerDN, "left, wrap");
        jpDisplayColumns.add(jcbEnableSubjectDN, "left");
        jpDisplayColumns.add(jcbEnableIssuerCN, "left, wrap");
        jpDisplayColumns.add(jcbEnableSubjectCN, "left");
        jpDisplayColumns.add(jcbEnableIssuerO, "left, wrap");
        jpDisplayColumns.add(jcbEnableSubjectO, "left");
        jpDisplayColumns.add(jcbEnableSerialNumberHex, "left, wrap");
        jpDisplayColumns.add(jcbEnableSerialNumberDec, "left, wrap para");
        jpDisplayColumns.add(jlExpirationWarnDays, "left, spanx, split");
        jpDisplayColumns.add(jspExpirationWarnDays, "wrap");

        return jpDisplayColumns;
    }

    JCheckBox getJcbEnableEntryName() {
        return jcbEnableEntryName;
    }

    JCheckBox getJcbEnableAlgorithm() {
        return jcbEnableAlgorithm;
    }

    JCheckBox getJcbEnableKeySize() {
        return jcbEnableKeySize;
    }

    JCheckBox getJcbEnableCertificateValidityStart() {
        return jcbEnableCertificateValidityStart;
    }

    JCheckBox getJcbEnableCertificateExpiry() {
        return jcbEnableCertificateExpiry;
    }

    JCheckBox getJcbEnableLastModified() {
        return jcbEnableLastModified;
    }

    JCheckBox getJcbEnableCurve() {
        return jcbEnableCurve;
    }

    JCheckBox getJcbEnableSKI() {
        return jcbEnableSKI;
    }

    JCheckBox getJcbEnableAKI() {
        return jcbEnableAKI;
    }

    JCheckBox getJcbEnableIssuerDN() {
        return jcbEnableIssuerDN;
    }

    JCheckBox getJcbEnableIssuerCN() {
        return jcbEnableIssuerCN;
    }

    JCheckBox getJcbEnableSubjectDN() {
        return jcbEnableSubjectDN;
    }

    JCheckBox getJcbEnableSubjectCN() {
        return jcbEnableSubjectCN;
    }

    JCheckBox getJcbEnableIssuerO() {
        return jcbEnableIssuerO;
    }

    JCheckBox getJcbEnableSubjectO() {
        return jcbEnableSubjectO;
    }

    JCheckBox getJcbEnableSerialNumberHex() {
        return jcbEnableSerialNumberHex;
    }

    JCheckBox getJcbEnableSerialNumberDec() {
        return jcbEnableSerialNumberDec;
    }

    JSpinner getJspExpirationWarnDays() {
        return jspExpirationWarnDays;
    }
}
