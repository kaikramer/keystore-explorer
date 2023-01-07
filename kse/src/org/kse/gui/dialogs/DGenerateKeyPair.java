/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
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
import javax.swing.JSeparator;
import javax.swing.JSpinner;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;

import org.kse.crypto.ecc.CurveSet;
import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.ecc.EdDSACurves;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.gui.JEscDialog;
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
    private JLabel jlRSAKeySize;
    private JSpinner jspRSAKeySize;

    private JRadioButton jrbDSA;
    private JLabel jlDSAKeySize;
    private JSpinner jspDSAKeySize;

    private JRadioButton jrbEC;
    private JLabel jlECCurveSet;
    private JComboBox<String> jcbECCurveSet;
    private JLabel jlECCurve;
    private JComboBox<String> jcbECCurve;

    private JButton jbOK;
    private JButton jbCancel;

    private final KeyPairType keyPairType;
    private final int keyPairSizeRSA;
    private final int keyPairSizeDSA;
    private final String keyPairCurveSet;
    private final String keyPairCurveName;
    private final KeyStoreType keyStoreType;

    private boolean success = false;

    /**
     * Creates a new DGenerateKeyPair dialog.
     *
     * @param parent           The parent frame
     * @param keyStoreType     Type of the key store for the new ke pair
     * @param keyPairType      Initial key pair type
     * @param keyPairSizeRSA   Initial key pair size
     * @param keyPairSizeDSA   Initial key pair size
     * @param keyPairCurveSet  Initially selected EC curve set
     * @param keyPairCurveName Initially selected named EC curve
     */
    public DGenerateKeyPair(JFrame parent, KeyStoreType keyStoreType, KeyPairType keyPairType, int keyPairSizeRSA,
                            int keyPairSizeDSA, String keyPairCurveSet, String keyPairCurveName) {

        super(parent, res.getString("DGenerateKeyPair.Title"), Dialog.ModalityType.DOCUMENT_MODAL);

        this.keyPairType = keyPairType;
        this.keyPairSizeRSA = keyPairSizeRSA;
        this.keyPairSizeDSA = keyPairSizeDSA;
        this.keyPairCurveSet = keyPairCurveSet;
        this.keyPairCurveName = keyPairCurveName;
        this.keyStoreType = keyStoreType;

        initComponents();
    }

    private void initComponents() {
        jlRSAKeySize = new JLabel(res.getString("DGenerateKeyPair.jlKeySize.text"));

        jspRSAKeySize = new JSpinner();
        jspRSAKeySize.setToolTipText(res.getString("DGenerateKeyPair.jsKeySize.tooltip"));

        jlDSAKeySize = new JLabel(res.getString("DGenerateKeyPair.jlKeySize.text"));

        jspDSAKeySize = new JSpinner();
        jspDSAKeySize.setToolTipText(res.getString("DGenerateKeyPair.jsKeySize.tooltip"));

        jrbRSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbRSA.text"), false);
        PlatformUtil.setMnemonic(jrbRSA, res.getString("DGenerateKeyPair.jrbRSA.mnemonic").charAt(0));
        jrbRSA.setToolTipText(res.getString("DGenerateKeyPair.jrbRSA.tooltip"));

        jrbDSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbDSA.text"), true);
        PlatformUtil.setMnemonic(jrbDSA, res.getString("DGenerateKeyPair.jrbDSA.mnemonic").charAt(0));
        jrbDSA.setToolTipText(res.getString("DGenerateKeyPair.jrbDSA.tooltip"));

        jrbEC = new JRadioButton(res.getString("DGenerateKeyPair.jrbEC.text"), true);
        PlatformUtil.setMnemonic(jrbEC, res.getString("DGenerateKeyPair.jrbEC.mnemonic").charAt(0));

        // EC available?
        if (EccUtil.isECAvailable(keyStoreType)) {
            jrbEC.setEnabled(true);
            jrbEC.setToolTipText(res.getString("DGenerateKeyPair.jrbEC.tooltip"));
        } else {
            jrbEC.setEnabled(false);
            jrbEC.setToolTipText(res.getString("DGenerateKeyPair.jrbEC.na.tooltip"));
        }

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(jrbRSA);
        buttonGroup.add(jrbDSA);
        buttonGroup.add(jrbEC);

        jlECCurveSet = new JLabel(res.getString("DGenerateKeyPair.jlECCurveSet.text"));
        jlECCurveSet.setToolTipText(res.getString("DGenerateKeyPair.jlECCurveSet.tooltip"));

        jcbECCurveSet = new JComboBox<>();
        jcbECCurveSet.setModel(new DefaultComboBoxModel<>(CurveSet.getAvailableSetNames(keyStoreType)));
        jcbECCurveSet.setToolTipText(res.getString("DGenerateKeyPair.jcbECCurveSet.tooltip"));

        jlECCurve = new JLabel(res.getString("DGenerateKeyPair.jlECCurve.text"));
        jlECCurve.setToolTipText(res.getString("DGenerateKeyPair.jlECCurve.tooltip"));

        jcbECCurve = new JComboBox<>();
        // make combo box wide enough for longest curve name
        jcbECCurve.setPrototypeDisplayValue(EccUtil.findLongestCurveName());
        jcbECCurve.setToolTipText(res.getString("DGenerateKeyPair.jcbECCurve.tooltip"));

        jbCancel = new JButton(res.getString("DGenerateKeyPair.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        jbOK = new JButton(res.getString("DGenerateKeyPair.jbOK.text"));

        if (keyPairType == KeyPairType.RSA) {
            jrbRSA.setSelected(true);
        } else if (keyPairType == KeyPairType.DSA) {
            jrbDSA.setSelected(true);
        } else {
            if (jrbEC.isEnabled()) {
                jrbEC.setSelected(true);
            } else {
                // EC not available => fall back to RSA
                jrbRSA.setSelected(true);
            }
        }

        loadKeySizes(keyPairSizeRSA, keyPairSizeDSA);
        loadECNamedCurves(keyPairCurveSet, keyPairCurveName);
        enableDisableElements();

        JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[][right][]", "[]unrel[]"));
        MiGUtil.addSeparator(pane, res.getString("DGenerateKeyPair.jpContent.text"));
        pane.add(jrbRSA, "");
        pane.add(jlRSAKeySize, "");
        pane.add(jspRSAKeySize, "growx, wrap");
        pane.add(jrbDSA, "");
        pane.add(jlDSAKeySize, "");
        pane.add(jspDSAKeySize, "growx, wrap");
        pane.add(jrbEC, "");
        pane.add(jlECCurveSet, "");
        pane.add(jcbECCurveSet, "growx, wrap");
        pane.add(jlECCurve, "skip");
        pane.add(jcbECCurve, "growx, wrap para");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jpButtons, "right, spanx");

        jcbECCurveSet.addItemListener(
                evt -> loadECNamedCurves((String) jcbECCurveSet.getModel().getSelectedItem(), keyPairCurveName));
        jrbRSA.addItemListener(evt -> enableDisableElements());
        jrbDSA.addItemListener(evt -> enableDisableElements());
        jrbEC.addItemListener(evt -> enableDisableElements());
        jspRSAKeySize.addChangeListener(evt -> correctKeyPairSize());
        jspDSAKeySize.addChangeListener(evt -> correctKeyPairSize());
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
                closeDialog();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void loadECNamedCurves(String curveSet, String keyPairCurveName) {
        CurveSet set = CurveSet.resolveName(curveSet);
        if (set == null) {
            set = CurveSet.resolveName((String) jcbECCurveSet.getModel().getSelectedItem());
        } else {
            jcbECCurveSet.getModel().setSelectedItem(curveSet);
        }

        List<String> curveNames = set.getAvailableCurveNames(keyStoreType);
        Collections.sort(curveNames);

        jcbECCurve.setModel(new DefaultComboBoxModel<>(curveNames.toArray(new String[0])));
        if (curveNames.contains(keyPairCurveName)) {
            jcbECCurve.getModel().setSelectedItem(keyPairCurveName);
        }
    }

    protected void enableDisableElements() {
        KeyPairType keyPairType = getKeyPairType();

        jlRSAKeySize.setEnabled(keyPairType == KeyPairType.RSA);
        jspRSAKeySize.setEnabled(keyPairType == KeyPairType.RSA);

        jlDSAKeySize.setEnabled(keyPairType == KeyPairType.DSA);
        jspDSAKeySize.setEnabled(keyPairType == KeyPairType.DSA);

        boolean isEcType = KeyPairType.EC_TYPES_SET.contains(keyPairType);
        jlECCurve.setEnabled(isEcType);
        jcbECCurve.setEnabled(isEcType);
        jlECCurveSet.setEnabled(isEcType);
        jcbECCurveSet.setEnabled(isEcType);
    }

    private void loadKeySizes(int keyPairSizeRSA, int keyPairSizeDSA) {
        keyPairSizeRSA = validateKeyPairSize(KeyPairType.RSA, keyPairSizeRSA);
        jspRSAKeySize.setModel(
                new SpinnerNumberModel(keyPairSizeRSA, KeyPairType.RSA.minSize(), KeyPairType.RSA.maxSize(),
                                       KeyPairType.RSA.stepSize()));

        keyPairSizeDSA = validateKeyPairSize(KeyPairType.DSA, keyPairSizeDSA);
        jspDSAKeySize.setModel(
                new SpinnerNumberModel(keyPairSizeDSA, KeyPairType.DSA.minSize(), KeyPairType.DSA.maxSize(),
                                       KeyPairType.DSA.stepSize()));
    }

    private void correctKeyPairSize() {
        KeyPairType keyPairType = getKeyPairType();
        if (keyPairType == KeyPairType.RSA) {
            int keyPairSizeRSA = getKeyPairSizeRSA();
            int validatedKeyPairSize = validateKeyPairSize(keyPairType, keyPairSizeRSA);
            if (validatedKeyPairSize != keyPairSizeRSA) {
                jspRSAKeySize.getModel().setValue(validatedKeyPairSize);
            }
        } else if (keyPairType == KeyPairType.DSA) {
            int keyPairSizeDSA = getKeyPairSizeDSA();
            int validatedKeyPairSize = validateKeyPairSize(keyPairType, keyPairSizeDSA);
            if (validatedKeyPairSize != keyPairSizeDSA) {
                jspDSAKeySize.getModel().setValue(validatedKeyPairSize);
            }
        }
    }

    private int validateKeyPairSize(KeyPairType keyPairType, int keyPairSize) {
        // Validate against step size
        int stepSize = keyPairType.stepSize();

        if ((keyPairSize % stepSize) != 0) {
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
        return ((Number) jspRSAKeySize.getValue()).intValue();
    }

    /**
     * Get the key pair size chosen.
     *
     * @return The key pair size
     */
    public int getKeyPairSizeDSA() {
        return ((Number) jspDSAKeySize.getValue()).intValue();
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
        return (String) jcbECCurve.getModel().getSelectedItem();
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

        // handle Ed25519 and Ed448
        if (jrbEC.isSelected() && CurveSet.ED.getVisibleName().equals(jcbECCurveSet.getModel().getSelectedItem())) {
            if (EdDSACurves.ED25519.jce().equals(jcbECCurve.getModel().getSelectedItem())) {
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
        DGenerateKeyPair dialog = new DGenerateKeyPair(new JFrame(), KeyStoreType.JKS, KeyPairType.RSA, 2048, 1024, "",
                                                       "");
        DialogViewer.run(dialog);
    }
}
