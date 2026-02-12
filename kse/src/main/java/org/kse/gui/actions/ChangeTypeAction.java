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
package org.kse.gui.actions;

import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JOptionPane;

import org.kse.crypto.CryptoException;
import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to change the active KeyStore's type.
 */
public class ChangeTypeAction extends KeyStoreExplorerAction implements HistoryAction {
    private static final long serialVersionUID = 1L;
    private KeyStoreType newType;
    private boolean warnNoChangeKey;
    private boolean warnNoECC;
    private boolean warnUnsupportedKey;
    private boolean warnDuplicateAlias;
    private Map<String, Integer> aliasSuffixes;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     * @param newType  New KeyStore type
     */
    public ChangeTypeAction(KseFrame kseFrame, KeyStoreType newType) {
        super(kseFrame);

        this.newType = newType;

        putValue(LONG_DESCRIPTION,
                 MessageFormat.format(res.getString("ChangeTypeAction.statusbar"), newType.friendly()));
        putValue(NAME, newType.friendly());
        putValue(SHORT_DESCRIPTION, newType.friendly());
    }

    @Override
    public String getHistoryDescription() {
        return MessageFormat.format(res.getString("ChangeTypeAction.History.text"), newType.friendly());
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        KeyStoreType currentType = KeyStoreType.resolveJce(
                kseFrame.getActiveKeyStoreHistory().getCurrentState().getKeyStore().getType());

        if (currentType == newType) {
            return;
        }

        aliasSuffixes = new HashMap<>();
        boolean changeResult = changeKeyStoreType(newType);

        if (!changeResult) {
            // Change type failed or cancelled - revert radio button menu item for KeyStore type
            kseFrame.updateControls(false);
        }
    }

    private boolean changeKeyStoreType(KeyStoreType newKeyStoreType) {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStoreState currentState = history.getCurrentState();

            KseKeyStore currentKeyStore = currentState.getKeyStore();

            KseKeyStore newKeyStore = KeyStoreUtil.create(newKeyStoreType);

            // Only warn the user once
            resetWarnings();

            // Copy all entries to the new KeyStore: Trusted certs, key pairs and secret keys
            for (Enumeration<String> aliases = currentKeyStore.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();

                if (KeyStoreUtil.isTrustedCertificateEntry(alias, currentKeyStore)) {
                    Certificate trustedCertificate = currentKeyStore.getCertificate(alias);

                    if (newKeyStore.containsAlias(alias)) {
                        showNoticeDuplicateAlias();
                        alias = renameAlias(newKeyStoreType.normalizeAlias(alias));
                    }

                    newKeyStore.setCertificateEntry(alias, trustedCertificate);
                } else if (KeyStoreUtil.isKeyPairEntry(alias, currentKeyStore)) {
                    if (!copyKeyPairEntry(newKeyStoreType, currentState, currentKeyStore, newKeyStore, alias)) {
                        return false;
                    }
                } else if (KeyStoreUtil.isKeyEntry(alias, currentKeyStore)) {
                    if (!copySecretKeyEntry(newKeyStoreType, currentState, currentKeyStore, newKeyStore, alias)) {
                        return false;
                    }
                }
            }

            KeyStoreState newState = currentState.createBasisForNextState(this);
            newState.setKeyStore(newKeyStore);

            currentState.append(newState);

            kseFrame.updateControls(true);

            JOptionPane.showMessageDialog(frame, res.getString("ChangeTypeAction.ChangeKeyStoreTypeSuccessful.message"),
                                          res.getString("ChangeTypeAction.ChangeKeyStoreType.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
            return true;
        } catch (Exception ex) {
            DError.displayError(frame, ex);
            return false;
        }
    }

    private void resetWarnings() {
        // Only warn the user once about key entries not being carried over by the change
        warnNoChangeKey = false;
        warnNoECC = false;
        warnUnsupportedKey = false;
        warnDuplicateAlias = false;
    }

    private boolean copyKeyPairEntry(KeyStoreType newKeyStoreType, KeyStoreState currentState, KseKeyStore currentKeyStore,
                                     KseKeyStore newKeyStore, String alias)
            throws KeyStoreException, CryptoException, NoSuchAlgorithmException, UnrecoverableKeyException {

        Certificate[] certificateChain = currentKeyStore.getCertificateChain(alias);
        certificateChain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certificateChain));

        Password password = getEntryPassword(alias, currentState);
        if (password == null) {
            return false;
        }

        Key privateKey = currentKeyStore.getKey(alias, password.toCharArray());

        // EC key pair? => might not be supported in target key store type
        if (KeyStoreUtil.isECKeyPair(alias, currentKeyStore)) {

            String namedCurve = EccUtil.getNamedCurve(currentKeyStore.getKey(alias, password.toCharArray()));

            // EC or curve not supported?
            if (!newKeyStoreType.supportsNamedCurve(namedCurve)) {

                // show warning and abort change or just skip depending on user choice
                return showWarnNoECC();
            }
        }

        if (newKeyStore.containsAlias(alias)) {
          showNoticeDuplicateAlias();
          alias = renameAlias(newKeyStoreType.normalizeAlias(alias));
        }

        currentState.setEntryPassword(alias, password);

        newKeyStore.setKeyEntry(alias, privateKey, password.toCharArray(), certificateChain);
        return true;
    }

    private boolean copySecretKeyEntry(KeyStoreType newKeyStoreType, KeyStoreState currentState,
                                       KseKeyStore currentKeyStore, KseKeyStore newKeyStore, String alias)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {

        if (newKeyStoreType.supportsKeyEntries()) {

            Password password = getEntryPassword(alias, currentState);

            if (password == null) {
                return false;
            }

            Key secretKey = currentKeyStore.getKey(alias, password.toCharArray());

            if (!newKeyStoreType.supportsKeyType(SecretKeyType.resolveJce(secretKey.getAlgorithm()))) {
                return showWarnUnsupportedKey();
            }

            if (newKeyStore.containsAlias(alias)) {
                showNoticeDuplicateAlias();
                alias = renameAlias(newKeyStoreType.normalizeAlias(alias));
            }

            currentState.setEntryPassword(alias, password);

            newKeyStore.setKeyEntry(alias, secretKey, password.toCharArray(), null);
        } else {
            // show warning and let user decide whether to abort (return false) or just skip the entry (true)
            return showWarnNoChangeKey();
        }

        return true;
    }

    private String renameAlias(String alias) {
        int suffix = aliasSuffixes.getOrDefault(alias, 0);
        aliasSuffixes.put(alias, ++suffix);
        return alias + "-" + String.valueOf(suffix);
    }

    private boolean showWarnNoECC() {
        if (!warnNoECC) {
            warnNoECC = true;
            int selected = JOptionPane.showConfirmDialog(frame, res.getString("ChangeTypeAction.WarnNoECC.message"),
                                                         res.getString("ChangeTypeAction.ChangeKeyStoreType.Title"),
                                                         JOptionPane.YES_NO_OPTION);

            if (selected != JOptionPane.YES_OPTION) {
                // user wants to abort
                return false;
            }
        }
        // do not add this entry to new key store
        return true;
    }

    private boolean showWarnNoChangeKey() {
        if (!warnNoChangeKey) {
            warnNoChangeKey = true;
            int selected = JOptionPane.showConfirmDialog(frame,
                                                         res.getString("ChangeTypeAction.WarnNoChangeKey.message"),
                                                         res.getString("ChangeTypeAction.ChangeKeyStoreType.Title"),
                                                         JOptionPane.YES_NO_OPTION);
            if (selected != JOptionPane.YES_OPTION) {
                return false;
            }
        }
        return true;
    }

    private boolean showWarnUnsupportedKey() {
        if (!warnUnsupportedKey) {
            warnUnsupportedKey = true;
            int selected = JOptionPane.showConfirmDialog(frame,
                    res.getString("ChangeTypeAction.WarnUnsupportedKey.message"),
                    res.getString("ChangeTypeAction.ChangeKeyStoreType.Title"),
                    JOptionPane.YES_NO_OPTION);
            if (selected != JOptionPane.YES_OPTION) {
                return false;
            }
        }
        return true;
    }

    private void showNoticeDuplicateAlias() {
        if (!warnDuplicateAlias) {
            warnDuplicateAlias = true;
            JOptionPane.showMessageDialog(frame,
                    res.getString("ChangeTypeAction.NotifyDuplicateAlias.message"),
                    res.getString("ChangeTypeAction.ChangeKeyStoreType.Title"),
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }
}
