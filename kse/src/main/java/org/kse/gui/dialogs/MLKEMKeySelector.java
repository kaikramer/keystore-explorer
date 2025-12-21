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

import java.util.Collection;
import java.util.ResourceBundle;

import javax.swing.ButtonGroup;

import org.kse.crypto.keypair.KeyPairType;

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
public class MLKEMKeySelector extends KeySelector {
    private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final long serialVersionUID = 1998L;

    /**
     * Constructs a new ML-KEM key selector UI elements.
     *
     * @param buttonGroup The button group to use for the ML-KEM radio button.
     * @param enabled     ML-KEM should only be enabled when key pair will not be self-signed.
     */
    public MLKEMKeySelector(ButtonGroup buttonGroup, boolean enabled) {
        super(buttonGroup, "MLKEMKeySelector");

        jrbKeyType.setEnabled(enabled);
        if (enabled) {
            jrbKeyType.setToolTipText(RESOURCE_BUNDLE.getString("MLKEMKeySelector.jrbKeyType.tooltip"));
        } else {
            jrbKeyType.setToolTipText(RESOURCE_BUNDLE.getString("MLKEMKeySelector.jrbKeyType.na.tooltip"));
        }
    }

    @Override
    protected Collection<KeyPairType> keyPairTypes() {
        return KeyPairType.MLKEM_TYPES_SET;
    }
}
