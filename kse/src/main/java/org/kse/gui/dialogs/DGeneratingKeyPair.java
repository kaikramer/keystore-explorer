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

import java.security.KeyPair;
import java.security.Provider;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.gui.error.DError;

/**
 * Generates a key pair which the user may cancel at any time by pressing the
 * cancel button.
 */
public class DGeneratingKeyPair extends JWaitDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private KeyPairType keyPairType;
    private int keySize;
    private String curveName;
    private KeyPair keyPair;

    private Provider provider;

    /**
     * Creates a new DGeneratingKeyPair dialog.
     *
     * @param parent      The parent frame
     * @param keyPairType The key pair generation type
     * @param keySize     The key size to generate
     * @param provider    The security provider to use
     */
    public DGeneratingKeyPair(JFrame parent, KeyPairType keyPairType, int keySize, Provider provider) {
        super(parent, res.getString("DGeneratingKeyPair.Title"), res.getString("DGeneratingKeyPair.jlGenKeyPair.text"),
                "images/genkp.png", res.getString("DGeneratingKeyPair.jbCancel.text"));
        this.keyPairType = keyPairType;
        this.keySize = keySize;
        this.provider = provider;
    }

    /**
     * Creates a new DGeneratingKeyPair dialog.
     *
     * @param parent      The parent frame
     * @param keyPairType The key pair generation type
     * @param provider    The security provider to use
     */
    public DGeneratingKeyPair(JFrame parent, KeyPairType keyPairType, Provider provider) {
        super(parent, "DGeneratingKeyPair.Title", "DGeneratingKeyPair.jlGenKeyPair.text", "images/genkp.png",
                "DGeneratingKeyPair.jbCancel.text");
        this.keyPairType = keyPairType;
        this.provider = provider;
    }


    /**
     * Creates a new DGeneratingKeyPair dialog.
     *
     * @param parent      The parent frame
     * @param keyPairType The key pair generation type
     * @param curveName   The name of the curve to create
     * @param provider    The security provider to use
     */
    public DGeneratingKeyPair(JFrame parent, KeyPairType keyPairType, String curveName, Provider provider) {
        super(parent, "DGeneratingKeyPair.Title", "DGeneratingKeyPair.jlGenKeyPair.text", "images/genkp.png",
                "DGeneratingKeyPair.jbCancel.text");
        this.keyPairType = keyPairType;
        this.curveName = curveName;
        this.provider = provider;
    }

    /**
     * Start key pair generation in a separate thread.
     */
    public void startKeyPairGeneration() {
        startTask(new GenerateKeyPair());
    }

    /**
     * Get the generated key pair.
     *
     * @return The generated key pair or null if the user cancelled the dialog
     *         or an error occurred
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    private class GenerateKeyPair implements Runnable {
        @Override
        public void run() {
            try {
                switch (keyPairType) {
                case RSA:
                case DSA:
                    keyPair = KeyPairUtil.generateKeyPair(keyPairType, keySize, provider);
                    break;
                case MLDSA44:
                case MLDSA65:
                case MLDSA87:
                case MLKEM512:
                case MLKEM768:
                case MLKEM1024:
                case SLHDSA_SHA2_128F:
                case SLHDSA_SHA2_128S:
                case SLHDSA_SHA2_192F:
                case SLHDSA_SHA2_192S:
                case SLHDSA_SHA2_256F:
                case SLHDSA_SHA2_256S:
                case SLHDSA_SHAKE_128F:
                case SLHDSA_SHAKE_128S:
                case SLHDSA_SHAKE_192F:
                case SLHDSA_SHAKE_192S:
                case SLHDSA_SHAKE_256F:
                case SLHDSA_SHAKE_256S:
                    keyPair = KeyPairUtil.generateKeyPair(keyPairType, provider);
                    break;
                case EC:
                case ECDSA:
                case EDDSA:
                case ED25519:
                case ED448:
                default:
                    keyPair = KeyPairUtil.generateECKeyPair(curveName, provider);
                    break;
                }

                SwingUtilities.invokeLater(() -> {
                    if (DGeneratingKeyPair.this.isShowing()) {
                        closeDialog();
                    }
                });
            } catch (final Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (DGeneratingKeyPair.this.isShowing()) {
                        DError dError = new DError(DGeneratingKeyPair.this, ex);
                        dError.setLocationRelativeTo(DGeneratingKeyPair.this);
                        dError.setVisible(true);
                        closeDialog();
                    }
                });
            }
        }
    }
}
