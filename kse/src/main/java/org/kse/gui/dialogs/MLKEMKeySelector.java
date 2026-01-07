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
 *
 */

package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.event.ItemListener;
import java.io.Serializable;
import java.util.ResourceBundle;

import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JRadioButton;

import org.kse.crypto.keypair.KeyPairType;
import org.kse.gui.PlatformUtil;

/**
 * UI elements used by {@link  org.kse.gui.dialogs.DGenerateKeyPair}
 * to generate ML-KEM key pairs
 * <p>
 * Holds a radio button and combo box for picking an ML-KEM {@link KeyPairType},
 * enabling/disabling the combo automatically.
 * </p>
 *
 * <pre>
 * {@code
 * MLKEMKeySelector mlKem = new MLKEMKeySelector(group);
 * mlKem.add(contentPane);
 *
 * if (mlKem.isSelected()) { // later, when OK pressed
 *     KeyPairType type = mlKem.getKeyPairType();
 * }
 * }
 * </pre>
 */
public class MLKEMKeySelector implements Serializable {
    private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final long serialVersionUID = 1998L;

    protected JRadioButton jRadioButton;
    protected JLabel jLabelKeyType;
    protected JComboBox<String> jComboBoxKeyType;

    /**
     * Constructs a new ML-KEM key selector UI elements.
     *
     * @param buttonGroup The button group to use for the ML-KEM radio button.
     * @param enabled     ML-KEM should only be enabled when key pair will not be self-signed.
     */
    public MLKEMKeySelector(ButtonGroup buttonGroup, boolean enabled) {

        jRadioButton = new JRadioButton(RESOURCE_BUNDLE.getString("MLKEMKeySelector.jRadioButton.text"));
        if (enabled) {
            jRadioButton.setToolTipText(RESOURCE_BUNDLE.getString("MLKEMKeySelector.jRadioButton.tooltip"));
        } else {
            jRadioButton.setToolTipText(RESOURCE_BUNDLE.getString("MLKEMKeySelector.jRadioButton.na.tooltip"));
        }
        PlatformUtil.setMnemonic(
                jRadioButton, RESOURCE_BUNDLE.getString("MLKEMKeySelector.jRadioButton.mnemonic").charAt(0));

        jLabelKeyType = new JLabel(RESOURCE_BUNDLE.getString("MLKEMKeySelector.jLabelKeyType.tooltip"));
        jLabelKeyType.setDisplayedMnemonic(RESOURCE_BUNDLE.getString("MLKEMKeySelector.jLabelKeyType.mnemonic").charAt(0));

        jComboBoxKeyType = new JComboBox<>();
        jComboBoxKeyType.setToolTipText(RESOURCE_BUNDLE.getString("MLKEMKeySelector.jComboBoxKeyType.tooltip"));
        jLabelKeyType.setLabelFor(jComboBoxKeyType);

        String[] names = KeyPairType.MLKEM_TYPES_SET.stream()
                .map(type -> DialogHelper.formatNameWithSize(type.jce(), type.maxSize()))
                .toArray(String[]::new);

        jComboBoxKeyType.setModel(new DefaultComboBoxModel<>(names));
        jRadioButton.setEnabled(enabled);
        jRadioButton.addItemListener(event -> enableDisableElements());
        setSelected(true);
        if (buttonGroup != null) {
            buttonGroup.add(jRadioButton);
        }
    }

    /**
     * Adds the ML-KEM controls the pane.
     *
     * @param pane The pane to add the controls to.
     */
    public void add(Container pane) {
        if (pane == null) {
            return;
        }
        pane.add(jRadioButton, "");
        pane.add(jLabelKeyType, "");
        pane.add(jComboBoxKeyType, "growx, wrap");
    }

    /**
     * Enable and disable the selector elements.
     */
    public void enableDisableElements() {
        jComboBoxKeyType.setEnabled(jRadioButton.isSelected());
    }

    /**
     * The preferred parameter set to use.
     *
     * @param keyType The KeyPairType.
     */
    public void setPreferredParameterSet(KeyPairType keyType) {
        if (KeyPairType.isMlKEM(keyType)) {
            jComboBoxKeyType.setSelectedItem(DialogHelper.formatNameWithSize(keyType.jce(), keyType.maxSize()));
        }
    }

    /**
     * Adds an item listener to the ML-KEM radio button. Allows the parent
     * panel to update controls when the ML-KEM radio button is selected.
     *
     * @param itemListener The item listener to add.
     */
    public void addItemListener(ItemListener itemListener) {
        jRadioButton.addItemListener(itemListener);
    }

    /**
     *
     * @return True if the ML-KEM radio button is selected. False if not.
     */
    public boolean isSelected() {
        return jRadioButton.isSelected();
    }

    /**
     * Selects the selected state of the ML-KEM radio button.
     *
     * @param selected The selected state.
     */
    public void setSelected(boolean selected) {
        jRadioButton.setSelected(selected);
        enableDisableElements();
    }

    /**
     *
     * @return The KeyPairType of the ML-KEM parameter set.
     */
    public KeyPairType getKeyPairType() {
        return KeyPairType
                .resolveJce(DialogHelper.extractNameFromFormatted((String) jComboBoxKeyType.getSelectedItem()));
    }

}
