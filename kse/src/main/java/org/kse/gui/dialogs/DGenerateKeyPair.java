/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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
package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;

import org.kse.crypto.ecc.CurveSet;
import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.ecc.EdDSACurves;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.preferences.data.KeyGenerationSettings;
import org.kse.gui.MiGUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to choose the parameters required for key pair generation. The
 * user may select an asymmetric key generation algorithm of RSA or DSA and
 * enter a key size in bits.
 */
public class DGenerateKeyPair extends JEscDialog {

    private static final long serialVersionUID = 7178673779995142190L;

    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JRadioButton jrbRSA;
    private JRadioButton jrbDSA;

    private JRadioButton jrbSize2048;
    private JRadioButton jrbSize3072;
    private JRadioButton jrbSize4096;
    private JRadioButton jrbSizeManual;
    private JSpinner jspSizeManual;

    private JRadioButton jrbEC;
    private JRadioButton jrbEdDSA;
    private JLabel jlECCurveSet;
    private JComboBox<String> jcbECCurveSet;
    private JLabel jlECCurve;
    private JComboBox<String> jcbECCurve;

    private JLabel jlEdDSACurve;
    private JComboBox<String> jcbEdDSACurve;

    private MLDSAKeySelector mldsaKeySelector;
    private MLKEMKeySelector mlkemKeySelector;
    private SlhDsaKeySelector slhDsaKeySelector;

    private final KeyPairType keyPairType;
    private final int keyPairSizeRSA;
    private final int keyPairSizeDSA;
    private final String keyPairCurveSet;
    private final String keyPairCurveName;
    private final KeyPairType mldsaParameterSet;
    private final KeyPairType mlkemParameterSet;
    private final KeyPairType slhDsaParameterSet;
    private final KeyStoreType keyStoreType;
    private final boolean isSelfSigned;

    private boolean success = false;

    /**
     * Creates a new DGenerateKeyPair dialog.
     *
     * @param parent       The parent frame
     * @param keyStoreType Type of the key store for the new key pair
     * @param defaults     Initial key pair type and parameters
     * @param isSelfSigned Indicates if the key pair is intended for a self signed
     *                     certificate.
     */
    public DGenerateKeyPair(JFrame parent, KeyStoreType keyStoreType, KeyGenerationSettings defaults,
            boolean isSelfSigned) {

        super(parent, res.getString("DGenerateKeyPair.Title"), Dialog.ModalityType.DOCUMENT_MODAL);

        this.keyPairType = defaults.getKeyPairType();
        this.keyPairSizeRSA = defaults.getKeyPairSizeRSA();
        this.keyPairSizeDSA = defaults.getKeyPairSizeDSA();
        this.keyPairCurveSet = defaults.getEcCurveSet();
        this.keyPairCurveName = defaults.getEcCurveName();
        this.mldsaParameterSet = defaults.getMLDSAParameterSet();
        this.mlkemParameterSet = defaults.getMLKEMParameterSet();
        this.slhDsaParameterSet = defaults.getSlhDsaParameterSet();
        this.keyStoreType = keyStoreType;
        this.isSelfSigned = isSelfSigned;

        initComponents();
    }

    private void initComponents() {
        JButton jbCancel;
        JButton jbOK;

        jrbSize2048 = new JRadioButton(res.getString("DGenerateKeyPair.Size.2048"));
        PlatformUtil.setMnemonic(jrbSize2048, res.getString("DGenerateKeyPair.jrbSize2048.mnemonic").charAt(0));
        jrbSize3072 = new JRadioButton(res.getString("DGenerateKeyPair.Size.3072"));
        PlatformUtil.setMnemonic(jrbSize3072, res.getString("DGenerateKeyPair.jrbSize3072.mnemonic").charAt(0));
        jrbSize4096 = new JRadioButton(res.getString("DGenerateKeyPair.Size.4096"));
        PlatformUtil.setMnemonic(jrbSize4096, res.getString("DGenerateKeyPair.jrbSize4096.mnemonic").charAt(0));
        jrbSizeManual = new JRadioButton(res.getString("DGenerateKeyPair.jrbSizeManual.text"));
        PlatformUtil.setMnemonic(jrbSizeManual, res.getString("DGenerateKeyPair.jrbSizeManual.mnemonic").charAt(0));
        jspSizeManual = new JSpinner();

        ButtonGroup sizeButtonGroup = new ButtonGroup();
        sizeButtonGroup.add(jrbSize2048);
        sizeButtonGroup.add(jrbSize3072);
        sizeButtonGroup.add(jrbSize4096);
        sizeButtonGroup.add(jrbSizeManual);

        jrbRSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbRSA.text"), false);
        PlatformUtil.setMnemonic(jrbRSA, res.getString("DGenerateKeyPair.jrbRSA.mnemonic").charAt(0));
        jrbRSA.setToolTipText(res.getString("DGenerateKeyPair.jrbRSA.tooltip"));

        jrbDSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbDSA.text"), true);
        PlatformUtil.setMnemonic(jrbDSA, res.getString("DGenerateKeyPair.jrbDSA.mnemonic").charAt(0));
        jrbDSA.setToolTipText(res.getString("DGenerateKeyPair.jrbDSA.tooltip"));

        jrbEC = new JRadioButton(res.getString("DGenerateKeyPair.jrbEC.text"), true);
        PlatformUtil.setMnemonic(jrbEC, res.getString("DGenerateKeyPair.jrbEC.mnemonic").charAt(0));
        jrbEC.setToolTipText(res.getString("DGenerateKeyPair.jrbEC.tooltip"));

        jrbEdDSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbEdDSA.text"), false);
        PlatformUtil.setMnemonic(jrbEdDSA, res.getString("DGenerateKeyPair.jrbEdDSA.mnemonic").charAt(0));
        jrbEdDSA.setToolTipText(res.getString("DGenerateKeyPair.jrbEdDSA.tooltip"));

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(jrbRSA);
        buttonGroup.add(jrbDSA);
        buttonGroup.add(jrbEC);
        buttonGroup.add(jrbEdDSA);

        jlECCurveSet = new JLabel(res.getString("DGenerateKeyPair.jlECCurveSet.text"));
        jlECCurveSet.setToolTipText(res.getString("DGenerateKeyPair.jlECCurveSet.tooltip"));
        jlECCurveSet.setDisplayedMnemonic(res.getString("DGenerateKeyPair.jlECCurveSet.mnemonic").charAt(0));
        
        jcbECCurveSet = new JComboBox<>();
        jcbECCurveSet.setToolTipText(res.getString("DGenerateKeyPair.jcbECCurveSet.tooltip"));
        jlECCurveSet.setLabelFor(jcbECCurveSet);
        
        jlECCurve = new JLabel(res.getString("DGenerateKeyPair.jlECCurve.text"));
        jlECCurve.setToolTipText(res.getString("DGenerateKeyPair.jlECCurve.tooltip"));
        jlECCurve.setDisplayedMnemonic(res.getString("DGenerateKeyPair.jlECCurve.mnemonic").charAt(0));

        jcbECCurve = new JComboBox<>();
        // make combo box wide enough for longest curve name with bit size
        jcbECCurve.setPrototypeDisplayValue(EccUtil.findLongestCurveName() + " (9999 bits)");
        jcbECCurve.setToolTipText(res.getString("DGenerateKeyPair.jcbECCurve.tooltip"));
        jlECCurve.setLabelFor(jcbECCurve);

        jlEdDSACurve = new JLabel(res.getString("DGenerateKeyPair.jlEdDSACurve.text"));
        jlEdDSACurve.setDisplayedMnemonic(res.getString("DGenerateKeyPair.jlEdDSACurve.mnemonic").charAt(0));

        String[] edDsaCurveNames = Collections.list(EdDSACurves.getNames()).toArray(new String[0]);
        for (int i = 0; i < edDsaCurveNames.length; i++) {
            KeyPairType type = KeyPairType.resolveJce(edDsaCurveNames[i]);
            edDsaCurveNames[i] = DialogHelper.formatNameWithSize(edDsaCurveNames[i], type.maxSize());
        }
        jcbEdDSACurve = new JComboBox<>(edDsaCurveNames);
        jcbEdDSACurve.setToolTipText(res.getString("DGenerateKeyPair.jcbEdDSACurve.tooltip"));
        jlEdDSACurve.setLabelFor(jcbEdDSACurve);

        jbCancel = new JButton(res.getString("DGenerateKeyPair.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        jbOK = new JButton(res.getString("DGenerateKeyPair.jbOK.text"));

        mldsaKeySelector = new MLDSAKeySelector(buttonGroup);
        mlkemKeySelector = new MLKEMKeySelector(buttonGroup, !isSelfSigned);
        slhDsaKeySelector = new SlhDsaKeySelector(buttonGroup);

        loadKeySizes(keyPairSizeRSA, keyPairSizeDSA);
        loadECNamedCurves(keyPairCurveSet, keyPairCurveName);
        mldsaKeySelector.setPreferredParameterSet(mldsaParameterSet);
        mlkemKeySelector.setPreferredParameterSet(mlkemParameterSet);
        slhDsaKeySelector.setPreferredParameterSet(slhDsaParameterSet);

        JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets dialog");

        JTabbedPane jtpAlgorithms = new JTabbedPane();
        jtpAlgorithms.addTab(res.getString("DGenerateKeyPair.Tab.Standard"), createStandardPanel());
        jtpAlgorithms.setMnemonicAt(0, res.getString("DGenerateKeyPair.Tab.Standard.mnemonic").charAt(0));
        jtpAlgorithms.addTab(res.getString("DGenerateKeyPair.Tab.EC"), createEcPanel());
        jtpAlgorithms.setMnemonicAt(1, res.getString("DGenerateKeyPair.Tab.EC.mnemonic").charAt(0));
        jtpAlgorithms.addTab(res.getString("DGenerateKeyPair.Tab.PQC"), createPqcPanel());
        jtpAlgorithms.setMnemonicAt(2, res.getString("DGenerateKeyPair.Tab.PQC.mnemonic").charAt(0));

        jtpAlgorithms.addChangeListener(evt -> {
            int index = jtpAlgorithms.getSelectedIndex();
            if (index == 0) { // STANDARD
                if (!jrbRSA.isSelected() && !jrbDSA.isSelected()) {
                    jrbRSA.setSelected(true);
                }
            } else if (index == 1) { // EC
                if (!jrbEC.isSelected() && !jrbEdDSA.isSelected()) {
                    jrbEC.setSelected(true);
                }
            } else if (index == 2) { // PQC
                if (!mldsaKeySelector.isSelected() && !mlkemKeySelector.isSelected()
                        && !slhDsaKeySelector.isSelected()) {
                    mldsaKeySelector.setSelected(true);
                }
            }
        });

        // layout
        Container pane = getContentPane();
        pane.setLayout(new BorderLayout());

        pane.add(jtpAlgorithms, BorderLayout.CENTER);
        pane.add(jpButtons, BorderLayout.SOUTH);

        focusKeyPair(jtpAlgorithms);

        mldsaKeySelector.addItemListener(evt -> enableDisableElements());
        mlkemKeySelector.addItemListener(evt -> enableDisableElements());
        slhDsaKeySelector.addItemListener(evt -> enableDisableElements());

        jcbECCurveSet.addItemListener(
                evt -> loadECNamedCurves((String) jcbECCurveSet.getModel().getSelectedItem(), keyPairCurveName));
        jrbRSA.addItemListener(evt -> enableDisableElements());
        jrbDSA.addItemListener(evt -> enableDisableElements());
        jrbEC.addItemListener(evt -> {
            if (jrbEC.isSelected()) {
                enableDisableElements();
            }
        });
        jrbEdDSA.addItemListener(evt -> {
            if (jrbEdDSA.isSelected()) {
                enableDisableElements();
            }
        });

        enableDisableElements();

        jrbSize2048.addActionListener(e -> jspSizeManual.setValue(2048));
        jrbSize3072.addActionListener(e -> jspSizeManual.setValue(3072));
        jrbSize4096.addActionListener(e -> jspSizeManual.setValue(4096));
        jrbSizeManual.addItemListener(e -> jspSizeManual.setEnabled(jrbSizeManual.isSelected()));

        jspSizeManual.addChangeListener(evt -> {
            int val = ((Number) jspSizeManual.getValue()).intValue();
            if (val == 2048) {
                jrbSize2048.setSelected(true);
            } else if (val == 3072) {
                jrbSize3072.setSelected(true);
            } else if (val == 4096) {
                jrbSize4096.setSelected(true);
            } else {
                jrbSizeManual.setSelected(true);
            }
            correctKeyPairSize();
        });

        jbOK.addActionListener(evt -> okPressed());
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                cancelPressed();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void focusKeyPair(JTabbedPane jtpAlgorithms) {
        if (keyPairType == KeyPairType.RSA) {
            jrbRSA.setSelected(true);
            jtpAlgorithms.setSelectedIndex(0);
        } else if (keyPairType == KeyPairType.DSA) {
            jrbDSA.setSelected(true);
            jtpAlgorithms.setSelectedIndex(0);
        } else if (keyPairType == KeyPairType.EC) {
            jrbEC.setSelected(true);
            jtpAlgorithms.setSelectedIndex(1);
        } else if (keyPairType == KeyPairType.ED25519 || keyPairType == KeyPairType.ED448) {
            jrbEdDSA.setSelected(true);
            jcbEdDSACurve.setSelectedItem(DialogHelper.formatNameWithSize(
                    keyPairType == KeyPairType.ED25519 ? EdDSACurves.ED25519.jce() : EdDSACurves.ED448.jce(),
                    keyPairType.maxSize()));
            jtpAlgorithms.setSelectedIndex(1);
        } else if (KeyPairType.isMlDSA(keyPairType)) {
            mldsaKeySelector.setSelected(true);
            jtpAlgorithms.setSelectedIndex(2);
        } else if (KeyPairType.isMlKEM(keyPairType) && !isSelfSigned) {
            // fall back to the default (RSA) for a self-signed key pair certificate
            mlkemKeySelector.setSelected(true);
            jtpAlgorithms.setSelectedIndex(2);
        } else if (KeyPairType.isSlhDsa(keyPairType)) {
            slhDsaKeySelector.setSelected(true);
            jtpAlgorithms.setSelectedIndex(2);
        } else {
            jrbRSA.setSelected(true);
            jtpAlgorithms.setSelectedIndex(0);
        }
    }

    private JPanel createStandardPanel() {
        JPanel jpStandard = new JPanel(new MigLayout("insets dialog, fillx", "[][grow]"));

        MiGUtil.addSeparator(jpStandard, res.getString("DGenerateKeyPair.Separator.Standard"));

        jpStandard.add(jrbRSA, "split 2");
        jpStandard.add(jrbDSA, "wrap");

        MiGUtil.addSeparator(jpStandard, res.getString("DGenerateKeyPair.KeySize"));

        jpStandard.add(jrbSize2048, "split 3");
        jpStandard.add(jrbSize3072, "");
        jpStandard.add(jrbSize4096, "wrap");
        jpStandard.add(jrbSizeManual, "split 2");
        jpStandard.add(jspSizeManual, "growx, wrap");

        return jpStandard;
    }

    private JPanel createEcPanel() {
        JPanel jpEc = new JPanel(new MigLayout("insets dialog, fillx", "[][right][grow]"));

        MiGUtil.addSeparator(jpEc, res.getString("DGenerateKeyPair.Separator.EC"));

        jpEc.add(jrbEC, "");
        jpEc.add(jlECCurveSet, "");
        jpEc.add(jcbECCurveSet, "growx, wrap");
        jpEc.add(new JLabel(""), ""); // spacer
        jpEc.add(jlECCurve, "");
        jpEc.add(jcbECCurve, "growx, wrap");

        MiGUtil.addSeparator(jpEc, res.getString("DGenerateKeyPair.Separator.EdwardsCurve"));
        jpEc.add(jrbEdDSA, "");
        jpEc.add(jlEdDSACurve, "");
        jpEc.add(jcbEdDSACurve, "growx, wrap");

        return jpEc;
    }

    private JPanel createPqcPanel() {
        JPanel jpPqc = new JPanel(new MigLayout("insets dialog, fillx", "[][right][grow]"));

        MiGUtil.addSeparator(jpPqc, res.getString("DGenerateKeyPair.Separator.PQC"));

        mldsaKeySelector.add(jpPqc);
        mlkemKeySelector.add(jpPqc);
        slhDsaKeySelector.add(jpPqc);

        return jpPqc;
    }

    private void loadECCurveSets() {
        String[] availableSets = CurveSet.getAvailableSetNames(keyStoreType);
        List<String> filteredSets = new ArrayList<>();

        for (String set : availableSets) {
            if (!set.equals(CurveSet.ED.getVisibleName())) {
                filteredSets.add(set);
            }
        }

        jcbECCurveSet.setModel(new DefaultComboBoxModel<>(filteredSets.toArray(new String[0])));
        loadECNamedCurves((String) jcbECCurveSet.getModel().getSelectedItem(), keyPairCurveName);
    }

    private void loadECNamedCurves(String curveSet, String keyPairCurveName) {
        CurveSet set = CurveSet.resolveName(curveSet);
        // Use the default curve set if the keystore type does not support the last used
        // curve set.
        if (!CurveSet.getAvailableSets(keyStoreType).contains(set)) {
            set = null;
        }
        if (set == null) {
            set = CurveSet.resolveName((String) jcbECCurveSet.getModel().getSelectedItem());
        } else {
            jcbECCurveSet.getModel().setSelectedItem(curveSet);
        }

        if (set == null) {
            jcbECCurve.setModel(new DefaultComboBoxModel<>());
            return;
        }

        List<String> curveNames = set.getAvailableCurveNames(keyStoreType);
        Collections.sort(curveNames);

        // Format curve names with bit sizes
        List<String> formattedCurveNames = new ArrayList<>();
        for (String curveName : curveNames) {
            formattedCurveNames.add(formatCurveNameWithSize(curveName));
        }

        jcbECCurve.setModel(new DefaultComboBoxModel<>(formattedCurveNames.toArray(String[]::new)));
        if (curveNames.contains(keyPairCurveName)) {
            jcbECCurve.getModel().setSelectedItem(formatCurveNameWithSize(keyPairCurveName));
        }
    }

    /**
     * Formats a curve name with its bit size for display.
     *
     * @param curveName The curve name
     * @return The formatted curve name with bit size (e.g., "secp256r1 (256 bits)")
     */
    private String formatCurveNameWithSize(String curveName) {
        return DialogHelper.formatNameWithSize(curveName, EccUtil.getCurveSize(curveName));
    }

    /**
     * Extracts the actual curve name from a formatted display string.
     *
     * @param formattedName The formatted curve name (e.g., "secp256r1 (256 bits)")
     * @return The actual curve name without the bit size
     */
    private String extractCurveNameFromFormatted(String formattedName) {
        return DialogHelper.extractNameFromFormatted(formattedName);
    }

    protected void enableDisableElements() {
        KeyPairType keyPairType = getKeyPairType();

        boolean isRsaOrDsa = keyPairType == KeyPairType.RSA || keyPairType == KeyPairType.DSA;

        jrbSize2048.setEnabled(isRsaOrDsa);
        jrbSize3072.setEnabled(isRsaOrDsa);
        jrbSize4096.setEnabled(isRsaOrDsa && keyPairType == KeyPairType.RSA);
        jrbSizeManual.setEnabled(isRsaOrDsa);

        if (isRsaOrDsa) {
            // Update spinner model with current algorithm's limits
            int currentVal = ((Number) jspSizeManual.getValue()).intValue();
            int validatedVal = validateKeyPairSize(keyPairType, currentVal);

            // Special case: if switching from 4096 (RSA) to DSA, default to 1024 as
            // requested
            if (currentVal == 4096 && keyPairType == KeyPairType.DSA) {
                validatedVal = 2048;
                jrbSize2048.setSelected(true);
            }

            jspSizeManual.setModel(new SpinnerNumberModel(validatedVal, keyPairType.minSize(), keyPairType.maxSize(),
                    keyPairType.stepSize()));
        }

        jspSizeManual.setEnabled(isRsaOrDsa && jrbSizeManual.isSelected());

        boolean isEcSelected = jrbEC.isSelected();
        boolean isEdDsaSelected = jrbEdDSA.isSelected();

        jlECCurve.setEnabled(isEcSelected);
        jcbECCurve.setEnabled(isEcSelected);
        jlECCurveSet.setEnabled(isEcSelected);
        jcbECCurveSet.setEnabled(isEcSelected);

        jlEdDSACurve.setEnabled(isEdDsaSelected);
        jcbEdDSACurve.setEnabled(isEdDsaSelected);

        // Selectors manage their own internal state
        mldsaKeySelector.enableDisableElements();
        mlkemKeySelector.enableDisableElements();
        slhDsaKeySelector.enableDisableElements();
    }

    private void loadKeySizes(int keyPairSizeRSA, int keyPairSizeDSA) {
        int keyPairSize = (keyPairType == KeyPairType.DSA) ? keyPairSizeDSA : keyPairSizeRSA;
        keyPairSize = validateKeyPairSize(keyPairType, keyPairSize);

        jspSizeManual.setModel(new SpinnerNumberModel(keyPairSize, keyPairType.minSize(), keyPairType.maxSize(),
                keyPairType.stepSize()));

        if (keyPairSize == 2048) {
            jrbSize2048.setSelected(true);
        } else if (keyPairSize == 3072) {
            jrbSize3072.setSelected(true);
        } else if (keyPairSize == 4096) {
            jrbSize4096.setSelected(true);
        } else {
            jrbSizeManual.setSelected(true);
        }

        loadECCurveSets();
    }

    private void correctKeyPairSize() {
        KeyPairType keyPairType = getKeyPairType();
        if (keyPairType == KeyPairType.RSA || keyPairType == KeyPairType.DSA) {
            int keyPairSize = ((Number) jspSizeManual.getValue()).intValue();
            int validatedKeyPairSize = validateKeyPairSize(keyPairType, keyPairSize);
            if (validatedKeyPairSize != keyPairSize) {
                jspSizeManual.getModel().setValue(validatedKeyPairSize);
            }
        }
    }

    private int validateKeyPairSize(KeyPairType keyPairType, int keyPairSize) {
        // Validate against step size
        int stepSize = keyPairType.stepSize();

        if (stepSize > 0 && (keyPairSize % stepSize) != 0) {
            int difference = keyPairSize % stepSize;

            if (difference <= (stepSize / 2)) {
                keyPairSize -= difference;
            } else {
                keyPairSize += (stepSize - difference);
            }
        }

        // Validate against minimum size
        int minSize = keyPairType.minSize();

        if (keyPairSize < minSize) {
            keyPairSize = minSize;
        }

        // Validate against maximum size
        int maxSize = keyPairType.maxSize();

        if (keyPairSize > maxSize) {
            keyPairSize = maxSize;
        }

        return keyPairSize;
    }

    /**
     * Get the key pair size chosen.
     *
     * @return The key pair size
     */
    public int getKeyPairSizeRSA() {
        return ((Number) jspSizeManual.getValue()).intValue();
    }

    /**
     * Get the key pair size chosen.
     *
     * @return The key pair size
     */
    public int getKeyPairSizeDSA() {
        return ((Number) jspSizeManual.getValue()).intValue();
    }

    /**
     * Get the name of the selected EC curve set.
     *
     * @return The curve set
     */
    public String getCurveSet() {
        return (String) jcbECCurveSet.getModel().getSelectedItem();
    }

    /**
     * Get the name of the selected curve.
     *
     * @return The curve name
     */
    public String getCurveName() {
        if (jrbEdDSA.isSelected()) {
            return DialogHelper.extractNameFromFormatted((String) jcbEdDSACurve.getModel().getSelectedItem());
        }
        String selectedItem = (String) jcbECCurve.getModel().getSelectedItem();
        return extractCurveNameFromFormatted(selectedItem);
    }

    /**
     * Get the key pair type chosen.
     *
     * @return The key pair generation type
     */
    public KeyPairType getKeyPairType() {
        if (jrbRSA.isSelected()) {
            return KeyPairType.RSA;
        }

        if (jrbDSA.isSelected()) {
            return KeyPairType.DSA;
        }

        if (mldsaKeySelector.isSelected()) {
            return mldsaKeySelector.getKeyPairType();
        }

        if (mlkemKeySelector.isSelected()) {
            return mlkemKeySelector.getKeyPairType();
        }

        if (slhDsaKeySelector.isSelected()) {
            return slhDsaKeySelector.getKeyPairType();
        }

        if (jrbEC.isSelected()) {
            String selectedCurveSet = (String) jcbECCurveSet.getModel().getSelectedItem();
            String selectedCurve = (String) jcbECCurve.getModel().getSelectedItem();

            if (selectedCurveSet == null || selectedCurve == null) {
                return KeyPairType.EC;
            }

            // handle ECGOST3410 and ECGOST3410-2012
            if (CurveSet.ECGOST.getVisibleName().equals(selectedCurveSet)) {
                return KeyPairType.getGostTypeFromCurve(selectedCurve);
            }
            return KeyPairType.EC;
        }

        if (jrbEdDSA.isSelected()) {
            String selectedCurve = DialogHelper
                    .extractNameFromFormatted((String) jcbEdDSACurve.getModel().getSelectedItem());
            if (EdDSACurves.ED25519.jce().equals(selectedCurve)) {
                return KeyPairType.ED25519;
            } else {
                return KeyPairType.ED448;
            }
        }

        return KeyPairType.EC;
    }

    /**
     * Have the parameters been entered correctly?
     *
     * @return True if they have, false otherwise
     */
    public boolean isSuccessful() {
        return success;
    }

    private void okPressed() {
        success = true;
        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick UI testing
    public static void main(String[] args) throws Exception {
        KeyGenerationSettings defaults = new KeyGenerationSettings();
        defaults.setKeyPairType(KeyPairType.RSA);
        defaults.setKeyPairSizeRSA(2048);
        defaults.setKeyPairSizeDSA(1024);
        defaults.setEcCurveSet("");
        defaults.setEcCurveName("");
        DGenerateKeyPair dialog = new DGenerateKeyPair(new JFrame(), KeyStoreType.BKS, defaults, false);
        DialogViewer.run(dialog);
    }
}
