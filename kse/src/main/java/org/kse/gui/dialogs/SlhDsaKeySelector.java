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
public class SlhDsaKeySelector extends KeySelector {
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new SLH-DSA key selector UI elements.
     *
     * @param buttonGroup The button group to use for the SLH-DSA radio button.
     */
    public SlhDsaKeySelector(ButtonGroup buttonGroup) {
        super(buttonGroup, "SlhDsaKeySelector");
    }

    @Override
    protected Collection<KeyPairType> keyPairTypes() {
        return KeyPairType.SLHDSA_TYPES_SET;
    }
}
