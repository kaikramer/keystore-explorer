/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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
 * to generate MLDSA key pairs
 * <p>
 * Holds a radio button and combo box for picking an ML-DSA {@link KeyPairType},
 * enabling/disabling the combo automatically.
 * </p>
 *
 * <pre>
 * {@code
 * MLDSAKeySelector mlDsa = new MLDSAKeySelector(group);
 * mlDsa.add(contentPane);
 *
 * if (mlDsa.isSelected()) { // later, when OK pressed
 *     KeyPairType type = mlDsa.getKeyPairType();
 * }
 * }
 * </pre>
 */
public class MLDSAKeySelector implements Serializable {
    private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle(
            "org/kse/gui/dialogs/resources");

    private static final long serialVersionUID = 1998L;

    protected JRadioButton jRadioButton;
    protected JLabel jLabelKeyType;
    protected JComboBox<String> jComboBoxKeyType;


    public MLDSAKeySelector(ButtonGroup buttonGroup) {

        jRadioButton = new JRadioButton(RESOURCE_BUNDLE.getString("MLDSAKeySelector.jRadioButton.text"));
        jRadioButton.setToolTipText(RESOURCE_BUNDLE.getString("MLDSAKeySelector.jRadioButton.tooltip"));
        PlatformUtil.setMnemonic(
                jRadioButton, RESOURCE_BUNDLE.getString("MLDSAKeySelector.jRadioButton.mnemonic").charAt(0));

        jLabelKeyType = new JLabel(RESOURCE_BUNDLE.getString("MLDSAKeySelector.jLabelKeyType.tooltip"));


        jComboBoxKeyType = new JComboBox<>();
        jComboBoxKeyType.setToolTipText(RESOURCE_BUNDLE.getString("MLDSAKeySelector.jComboBoxKeyType.tooltip"));


        String[] names = KeyPairType.MLDSA_TYPES_SET.stream()
                .map(KeyPairType::jce)
                .toArray(String[]::new);

        jComboBoxKeyType.setModel(new DefaultComboBoxModel<>(names));
        jRadioButton.setEnabled(true);
        jRadioButton.addItemListener(event -> enableDisableElements());
        this.setSelected(true);
        if (buttonGroup != null) {
            buttonGroup.add(jRadioButton);
        }
    }

    public void add(Container pane) {
        if (pane == null) {
            return;
        }
        pane.add(jRadioButton, "");
        pane.add(jLabelKeyType, "");
        pane.add(jComboBoxKeyType, "growx, wrap");
    }

    public void enableDisableElements() {
        jComboBoxKeyType.setEnabled(jRadioButton.isSelected());
    }

    public void setPreferredParameterSet(KeyPairType keyType) {
        if (KeyPairType.isMlDSA(keyType)) {
            jComboBoxKeyType.setSelectedItem(keyType.jce());
        }
    }

    public void addItemListener(ItemListener itemListener) {
        jRadioButton.addItemListener(itemListener);
    }

    public boolean isSelected() {
        return jRadioButton.isSelected();
    }

    public void setEnabled(boolean enabled) {
        jRadioButton.setEnabled(enabled);
        enableDisableElements();
    }

    public void setSelected(boolean selected) {
        jRadioButton.setSelected(selected);
        enableDisableElements();
    }

    public KeyPairType getKeyPairType() {
        return KeyPairType.resolveJce((String) jComboBoxKeyType.getSelectedItem());
    }

}
