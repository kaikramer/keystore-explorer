/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
package org.kse.gui.actions;

import java.awt.Toolkit;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DGenerateKeyPair;
import org.kse.gui.dialogs.DGenerateKeyPairCert;
import org.kse.gui.dialogs.DGeneratingKeyPair;
import org.kse.gui.dialogs.DGetAlias;
import org.kse.gui.error.DError;
import org.kse.gui.password.DGetNewPassword;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to generate a key pair.
 */
public class GenerateKeyPairAction extends KeyStoreExplorerAction implements HistoryAction {
    private static final long serialVersionUID = 1L;

    private final KseFrame kseFrame;
    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public GenerateKeyPairAction(KseFrame kseFrame) {
        super(kseFrame);
        this.kseFrame = kseFrame;
        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('G',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        putValue(LONG_DESCRIPTION, res.getString("GenerateKeyPairAction.statusbar"));
        putValue(NAME, res.getString("GenerateKeyPairAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("GenerateKeyPairAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/genkeypair.png"))));
    }

    @Override
    public String getHistoryDescription() {
        return (String) getValue(NAME);
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        generateKeyPair();
    }

    /**
     * Generate a key pair (with certificate) in the currently opened KeyStore.
     */
    public void generateKeyPair() {
        generateKeyPair(null, null, null);
    }

    /**
     * Generate a key pair (with certificate) in the currently opened KeyStore.
     *
     * @param issuerCert       Issuer certificate for signing the new certificate
     * @param issuerCertChain  Chain of issuer certificate
     * @param issuerPrivateKey Issuer's private key for signing
     * @return Alias of new key pair
     */
    public String generateKeyPair(X509Certificate issuerCert, X509Certificate[] issuerCertChain,
                                  PrivateKey issuerPrivateKey) {

        String alias = "";
        try {
            // Restore preferences regarding key type and length (or EC curve)
            KeyPairType keyPairType = preferences.getKeyGenerationDefaults().getKeyPairType();
            int keyPairSizeRSA = preferences.getKeyGenerationDefaults().getKeyPairSizeRSA();
            int keyPairSizeDSA = preferences.getKeyGenerationDefaults().getKeyPairSizeDSA();
            String keyPairCurveSet = preferences.getKeyGenerationDefaults().getEcCurveSet();
            String keyPairCurveName = preferences.getKeyGenerationDefaults().getEcCurveName();

            KeyStore activeKeyStore = kseFrame.getActiveKeyStore();
            KeyStoreType activeKeyStoreType = KeyStoreType.resolveJce(activeKeyStore.getType());
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            Provider provider = history.getExplicitProvider();

            DGenerateKeyPair dGenerateKeyPair = new DGenerateKeyPair(frame, activeKeyStoreType, keyPairType,
                                                                     keyPairSizeRSA, keyPairSizeDSA, keyPairCurveSet,
                                                                     keyPairCurveName);
            dGenerateKeyPair.setLocationRelativeTo(frame);
            dGenerateKeyPair.setVisible(true);

            if (!dGenerateKeyPair.isSuccessful()) {
                return "";
            }

            // update (saved) values from user selection
            keyPairType = dGenerateKeyPair.getKeyPairType();
            keyPairSizeRSA = dGenerateKeyPair.getKeyPairSizeRSA();
            keyPairSizeDSA = dGenerateKeyPair.getKeyPairSizeDSA();
            keyPairCurveSet = dGenerateKeyPair.getCurveSet();
            keyPairCurveName = dGenerateKeyPair.getCurveName();
            preferences.getKeyGenerationDefaults().setKeyPairType(keyPairType);
            preferences.getKeyGenerationDefaults().setKeyPairSizeRSA(keyPairSizeRSA);
            preferences.getKeyGenerationDefaults().setKeyPairSizeDSA(keyPairSizeDSA);
            preferences.getKeyGenerationDefaults().setEcCurveSet(keyPairCurveSet);
            preferences.getKeyGenerationDefaults().setEcCurveName(keyPairCurveName);

            KeyPair keyPair = generateKeyPair(keyPairType, keyPairSizeRSA, keyPairSizeDSA, keyPairCurveName, provider);
            if (keyPair == null) {
                return "";
            }

            DGenerateKeyPairCert dGenerateKeyPairCert = new DGenerateKeyPairCert(frame, kseFrame, res.getString(
                    "GenerateKeyPairAction.GenerateKeyPairCert.Title"), keyPair, keyPairType, issuerCert,
                                                                                 issuerPrivateKey, provider);
            dGenerateKeyPairCert.setLocationRelativeTo(frame);
            dGenerateKeyPairCert.setVisible(true);

            X509Certificate certificate = dGenerateKeyPairCert.getCertificate();

            if (certificate == null) {
                return "";
            }

            KeyStoreState currentState = history.getCurrentState();
            KeyStoreState newState = currentState.createBasisForNextState(this);

            KeyStore keyStore = newState.getKeyStore();

            DGetAlias dGetAlias = new DGetAlias(frame,
                                                res.getString("GenerateKeyPairAction.NewKeyPairEntryAlias.Title"),
                                                X509CertUtil.getCertificateAlias(certificate));
            dGetAlias.setLocationRelativeTo(frame);
            dGetAlias.setVisible(true);
            alias = dGetAlias.getAlias();

            if (alias == null) {
                return "";
            }

            if (keyStore.containsAlias(alias)) {
                String message = MessageFormat.format(res.getString("GenerateKeyPairAction.OverWriteEntry.message"),
                                                      alias);

                int selected = JOptionPane.showConfirmDialog(frame, message, res.getString(
                        "GenerateKeyPairAction.NewKeyPairEntryAlias.Title"), JOptionPane.YES_NO_OPTION);
                if (selected != JOptionPane.YES_OPTION) {
                    return "";
                }
            }

            Password password = new Password((char[]) null);
            KeyStoreType keyStoreType = KeyStoreType.resolveJce(activeKeyStore.getType());

            if (keyStoreType.hasEntryPasswords()) {
                DGetNewPassword dGetNewPassword = new DGetNewPassword(frame, res.getString(
                        "GenerateKeyPairAction.NewKeyPairEntryPassword.Title"), preferences);
                dGetNewPassword.setLocationRelativeTo(frame);
                dGetNewPassword.setVisible(true);
                password = dGetNewPassword.getPassword();

                if (password == null) {
                    return "";
                }
            }

            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
                newState.removeEntryPassword(alias);
            }

            // create new chain with certificates from issuer chain
            X509Certificate[] newCertChain = null;
            if (issuerCertChain != null) {
                newCertChain = new X509Certificate[issuerCertChain.length + 1];
                System.arraycopy(issuerCertChain, 0, newCertChain, 1, issuerCertChain.length);
                newCertChain[0] = certificate;
            } else {
                newCertChain = new X509Certificate[] { certificate };
            }

            keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), newCertChain);
            newState.setEntryPassword(alias, password);

            currentState.append(newState);

            kseFrame.updateControls(true);

            JOptionPane.showMessageDialog(frame,
                                          res.getString("GenerateKeyPairAction.KeyPairGenerationSuccessful.message"),
                                          res.getString("GenerateKeyPairAction.GenerateKeyPair.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }

        return alias;
    }

    private KeyPair generateKeyPair(KeyPairType keyPairType, int keyPairSizeRSA, int keyPairSizeDSA, String curveName,
                                    Provider provider) {
        DGeneratingKeyPair dGeneratingKeyPair;

        switch (keyPairType) {
        case RSA:
            dGeneratingKeyPair = new DGeneratingKeyPair(frame, keyPairType, keyPairSizeRSA, provider);
            break;
        case DSA:
            dGeneratingKeyPair = new DGeneratingKeyPair(frame, keyPairType, keyPairSizeDSA, provider);
            break;
        case EC:
        case ECDSA:
        case EDDSA:
        case ED25519:
        case ED448:
        default:
            dGeneratingKeyPair = new DGeneratingKeyPair(frame, keyPairType, curveName, provider);
            break;
        }

        dGeneratingKeyPair.setLocationRelativeTo(frame);
        dGeneratingKeyPair.startKeyPairGeneration();
        dGeneratingKeyPair.setVisible(true);

        return dGeneratingKeyPair.getKeyPair();
    }
}
