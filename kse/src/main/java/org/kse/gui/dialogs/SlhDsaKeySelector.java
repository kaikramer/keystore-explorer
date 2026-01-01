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
 * UI elements used by {@link org.kse.gui.dialogs.DGenerateKeyPair}
 * to generate SLH-DSA key pairs
 * <p>
 * Holds a radio button and combo box for picking an SLH-DSA {@link KeyPairType},
 * enabling/disabling the combo automatically.
 * </p>
 *
 * <pre>
 * {@code
 * SlhDsaKeySelector slhDsa = new SlhDsaKeySelector(group);
 * slhDsa.add(contentPane);
 *
 * if (slhDsa.isSelected()) { // later, when OK pressed
 *     KeyPairType type = slhDsa.getKeyPairType();
 * }
 * }
 * </pre>
 */
public class SlhDsaKeySelector implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    protected JRadioButton jrbKeyType;
    protected JLabel jlKeyType;
    protected JComboBox<String> jcbParameterSet;

    /**
     * Constructs a new SLH-DSA key selector UI elements.
     *
     * @param buttonGroup The button group to use for the SLH-DSA radio button.
     */
    public SlhDsaKeySelector(ButtonGroup buttonGroup) {

        jrbKeyType = new JRadioButton(RESOURCE_BUNDLE.getString("SlhDsaKeySelector.jrbKeyType.text"));
        jrbKeyType.setToolTipText(RESOURCE_BUNDLE.getString("SlhDsaKeySelector.jrbKeyType.tooltip"));
        PlatformUtil.setMnemonic(
                jrbKeyType, RESOURCE_BUNDLE.getString("SlhDsaKeySelector.jrbKeyType.mnemonic").charAt(0));

        jlKeyType = new JLabel(RESOURCE_BUNDLE.getString("SlhDsaKeySelector.jlKeyType.tooltip"));

        jcbParameterSet = new JComboBox<>();
        jcbParameterSet.setToolTipText(RESOURCE_BUNDLE.getString("SlhDsaKeySelector.jcbParameterSet.tooltip"));


        String[] names = KeyPairType.SLHDSA_TYPES_SET.stream()
                .map(KeyPairType::jce)
                .toArray(String[]::new);

        jcbParameterSet.setModel(new DefaultComboBoxModel<>(names));
        jrbKeyType.setEnabled(true);
        jrbKeyType.addItemListener(event -> enableDisableElements());
        this.setSelected(true);
        if (buttonGroup != null) {
            buttonGroup.add(jrbKeyType);
        }
    }

    /**
     * Adds the SLH-DSA controls the pane.
     *
     * @param pane The pane to add the controls to.
     */
    public void add(Container pane) {
        if (pane == null) {
            return;
        }
        pane.add(jrbKeyType, "");
        pane.add(jlKeyType, "");
        pane.add(jcbParameterSet, "growx, wrap");
    }

    /**
     * Enable and disable the selector elements.
     */
    public void enableDisableElements() {
        jcbParameterSet.setEnabled(jrbKeyType.isSelected());
    }

    /**
     * The preferred parameter set to use.
     *
     * @param keyType The KeyPairType.
     */
    public void setPreferredParameterSet(KeyPairType keyType) {
        if (KeyPairType.isSlhDsa(keyType)) {
            jcbParameterSet.setSelectedItem(keyType.jce());
        }
    }

    /**
     * Adds an item listener to the SLH-DSA radio button. Allows the parent
     * panel to update controls when the SLH-DSA radio button is selected.
     *
     * @param itemListener The item listener to add.
     */
    public void addItemListener(ItemListener itemListener) {
        jrbKeyType.addItemListener(itemListener);
    }

    /**
     *
     * @return True if the SLH-DSA radio button is selected. False if not.
     */
    public boolean isSelected() {
        return jrbKeyType.isSelected();
    }

    /**
     * Selects the selected state of the SLH-DSA radio button.
     *
     * @param selected The selected state.
     */
    public void setSelected(boolean selected) {
        jrbKeyType.setSelected(selected);
        enableDisableElements();
    }

    /**
     *
     * @return The KeyPairType of the SLH-DSA parameter set.
     */
    public KeyPairType getKeyPairType() {
        return KeyPairType.resolveJce((String) jcbParameterSet.getSelectedItem());
    }

}
