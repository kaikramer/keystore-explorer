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
import java.util.Collection;
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
 * to generate PQ key pairs
 * <p>
 * Holds a radio button and combo box for picking a PQ {@link KeyPairType},
 * enabling/disabling the combo automatically.
 * </p>
 */
public abstract class KeySelector implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    protected JRadioButton jrbKeyType;
    protected JLabel jlKeyType;
    protected JComboBox<String> jcbParameterSet;

    /**
     * Constructs a new key selector UI elements.
     *
     * @param buttonGroup The button group to use for the selector radio button.
     * @param resourcePrefix The resource prefix for the selector resource strings.
     */
    public KeySelector(ButtonGroup buttonGroup, String resourcePrefix) {

        jrbKeyType = new JRadioButton(RESOURCE_BUNDLE.getString(resourcePrefix + ".jrbKeyType.text"));
        jrbKeyType.setToolTipText(RESOURCE_BUNDLE.getString(resourcePrefix + ".jrbKeyType.tooltip"));
        PlatformUtil.setMnemonic(
                jrbKeyType, RESOURCE_BUNDLE.getString(resourcePrefix + ".jrbKeyType.mnemonic").charAt(0));

        jlKeyType = new JLabel(RESOURCE_BUNDLE.getString(resourcePrefix + ".jlKeyType.tooltip"));
        jlKeyType.setDisplayedMnemonic(RESOURCE_BUNDLE.getString(resourcePrefix + ".jlKeyType.mnemonic").charAt(0));

        jcbParameterSet = new JComboBox<>();
        jcbParameterSet.setToolTipText(RESOURCE_BUNDLE.getString(resourcePrefix + ".jcbParameterSet.tooltip"));
        jlKeyType.setLabelFor(jcbParameterSet);

        String[] names = keyPairTypes().stream()
                .map(type -> DialogHelper.formatNameWithSize(type.jce(), type.maxSize()))
                .toArray(String[]::new);

        jcbParameterSet.setModel(new DefaultComboBoxModel<>(names));
        jrbKeyType.setEnabled(true);
        jrbKeyType.addItemListener(event -> enableDisableElements());
        this.setSelected(true);
        if (buttonGroup != null) {
            buttonGroup.add(jrbKeyType);
        }
    }

    protected abstract Collection<KeyPairType> keyPairTypes();

    /**
     * Adds the selector controls to the pane.
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
        if (keyPairTypes().contains(keyType)) {
            jcbParameterSet.setSelectedItem(DialogHelper.formatNameWithSize(keyType.jce(), keyType.maxSize()));
        }
    }

    /**
     * Adds an item listener to the selector radio button. Allows the parent
     * panel to update controls when the selector radio button is selected.
     *
     * @param itemListener The item listener to add.
     */
    public void addItemListener(ItemListener itemListener) {
        jrbKeyType.addItemListener(itemListener);
    }

    /**
     *
     * @return True if the selector radio button is selected. False if not.
     */
    public boolean isSelected() {
        return jrbKeyType.isSelected();
    }

    /**
     * Selects the selected state of the selector radio button.
     *
     * @param selected The selected state.
     */
    public void setSelected(boolean selected) {
        jrbKeyType.setSelected(selected);
        enableDisableElements();
    }

    /**
     *
     * @return The KeyPairType of the selector parameter set.
     */
    public KeyPairType getKeyPairType() {
        return KeyPairType
                .resolveJce(DialogHelper.extractNameFromFormatted((String) jcbParameterSet.getSelectedItem()));
    }

}
