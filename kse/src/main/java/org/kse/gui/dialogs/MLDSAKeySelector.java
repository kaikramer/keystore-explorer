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

import javax.swing.ButtonGroup;

import org.kse.crypto.keypair.KeyPairType;

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
public class MLDSAKeySelector extends KeySelector {
    private static final long serialVersionUID = 1998L;

    /**
     * Constructs a new ML-DSA key selector UI elements.
     *
     * @param buttonGroup The button group to use for the ML-DSA radio button.
     */
    public MLDSAKeySelector(ButtonGroup buttonGroup) {
        super(buttonGroup, "MLDSAKeySelector");
    }

    @Override
    protected Collection<KeyPairType> keyPairTypes() {
        return KeyPairType.MLDSA_TYPES_SET;
    }
}
