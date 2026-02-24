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

import static org.kse.crypto.keystore.KeyStoreType.KEYCHAIN;
import static org.kse.crypto.keystore.KeyStoreType.MS_CAPI_PERSONAL;
import static org.kse.crypto.keystore.KeyStoreType.MS_CAPI_ROOT;
import static org.kse.crypto.keystore.KeyStoreType.PKCS11;

import java.awt.Toolkit;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.NoSuchFileException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.SecretKey;
import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.CryptoException;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.keystore.MsCapiStoreType;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.preferences.PreferencesManager;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to reload a KeyStore.
 */
public class ReloadAction extends KeyStoreExplorerAction implements HistoryAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public ReloadAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('R', Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        putValue(LONG_DESCRIPTION, res.getString("ReloadAction.statusbar"));
        putValue(NAME, res.getString("ReloadAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("ReloadAction.tooltip"));
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/open.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {

        KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
        KeyStoreState currentState = history.getCurrentState();

        if (currentState.getType().isFileBased()) {
            reloadFileBased(history, currentState, false);
        } else {
            reloadSpecial(history, currentState);
        }
    }

    public void reloadFileBased(KeyStoreHistory history, KeyStoreState currentState, boolean automatic) {
        File file = history.getFile();
        if (file != null) {
            try {
                KsePreferences prefs = PreferencesManager.getPreferences();
                KeyStoreState newState = currentState.createBasisForNextState(this);

                try {
                    history.setExternallyModified(false);

                    KseKeyStore keyStore = KeyStoreUtil.load(file, newState.getPassword());
                    if (!isEqual(keyStore, newState.getKeyStore(), newState)) {

                        // Prompt for automatic reload, unless silent
                        if (automatic && !prefs.isSilentlyReload()) {
                            int selected = JOptionPane.showConfirmDialog(frame, res.getString("ReloadAction.KeyStoreChanged.message"),
                                    res.getString("ReloadAction.ReloadKeyStore.Title"), JOptionPane.YES_NO_OPTION);

                            if (selected != JOptionPane.YES_OPTION) {
                                return;
                            }
                        }

                        // Prompt for unsaved changes to the current key store
                        if (!currentState.isSavedState()) {
                            String messageKey = "ReloadAction.KeyStoreUnsavedChanges.message";
                            if (automatic && prefs.isSilentlyReload()) {
                                messageKey = "ReloadAction.KeyStoreUnsavedChangesAutomatic.message";
                            }
                            int selected = JOptionPane.showConfirmDialog(frame,
                                    res.getString(messageKey),
                                    res.getString("ReloadAction.ReloadKeyStore.Title"),
                                    JOptionPane.YES_NO_OPTION);

                            if (selected != JOptionPane.YES_OPTION) {
                                return;
                            }
                        }

                        newState.setKeyStore(keyStore);
                        newState.setAsSavedState();

                        currentState.append(newState);
                        kseFrame.updateControls(true);
                    }

                    if (!prefs.isSilentlyReload()) {
                        JOptionPane.showMessageDialog(frame,
                                res.getString("ReloadAction.ReloadSuccessful.message"),
                                res.getString("ReloadAction.ReloadKeyStore.Title"),
                                JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (FileNotFoundException | NoSuchFileException e) {
                    JOptionPane.showMessageDialog(frame,
                            MessageFormat.format(res.getString("ReloadAction.NoReadFile.message"), file),
                            res.getString("ReloadAction.ReloadKeyStore.Title"), JOptionPane.WARNING_MESSAGE);

                    // Make the new state the current state so that the "unsaved file"
                    // indicator is displayed since the file backing this key store has
                    // disappeared.
                    currentState.append(newState);
                    kseFrame.updateControls(true);
                }
            } catch (CryptoException e) {
                DError.displayError(frame, e);
            }
        }
    }

    private void reloadSpecial(KeyStoreHistory history, KeyStoreState currentState) {
        try {
            KseKeyStore keyStore = null;

            KeyStoreType keyStoreType = currentState.getType();
            if (keyStoreType == MS_CAPI_PERSONAL) {
                keyStore = KeyStoreUtil.loadMsCapiStore(MsCapiStoreType.PERSONAL);
            } else if (keyStoreType == MS_CAPI_ROOT) {
                keyStore = KeyStoreUtil.loadMsCapiStore(MsCapiStoreType.ROOT);
            } else if (keyStoreType == KEYCHAIN) {
                keyStore = KeyStoreUtil.loadAppleKeychain();
            } else if (keyStoreType == PKCS11) {
                keyStore = KeyStoreUtil.loadPkcs11Store(frame, history.getExplicitProvider());
            }

            if (keyStore != null) {
                currentState.setKeyStore(keyStore);

                kseFrame.updateControls(true);

                JOptionPane.showMessageDialog(frame,
                        res.getString("ReloadAction.ReloadSuccessful.message"),
                        res.getString("ReloadAction.ReloadKeyStore.Title"),
                        JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (CryptoException e) {
            DError.displayError(frame, e);
        }
    }

    @Override
    public String getHistoryDescription() {
        return (String) getValue(NAME);
    }

    private record CanonicalEntry(
            String alias,
            String entryType,
            List<byte[]> certChain,
            byte[] trustedCert,
            byte[] privateKey,
            Map<String, String> attributes
    ) {};

    private boolean isEqual(KseKeyStore ks1, KseKeyStore ks2, KeyStoreState currentState) {

        Map<String, CanonicalEntry> map1 = null;
        Map<String, CanonicalEntry> map2 = null;
        try {
            map1 = canonicalizeKeyStore(ks1, currentState);
        } catch (GeneralSecurityException e) {
            // Ignore failure to read.
        }
        try {
            map2 = canonicalizeKeyStore(ks2, currentState);
        } catch (GeneralSecurityException e) {
            // Ignore failure to read.
        }

        // It is not possible to compare to null key stores so return in that case.
        return map1 != null && map2 != null && map1.equals(map2);
    }

    private Map<String, CanonicalEntry> canonicalizeKeyStore(KseKeyStore ks, KeyStoreState currentState)
            throws GeneralSecurityException {

        Map<String, CanonicalEntry> result = new TreeMap<>();

        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
            String alias = e.nextElement();
            Password password = currentState.getEntryPassword(alias);
            if (password == null) {
                password = currentState.getPassword();
            }

            KeyStore.Entry entry = ks.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
            result.put(alias, canonicalizeEntry(alias, entry));
        }

        return result;
    }

    private CanonicalEntry canonicalizeEntry(String alias, KeyStore.Entry entry) throws CertificateEncodingException {

        List<byte[]> certChain = List.of();
        byte[] trustedCert = null;
        byte[] key = null;
        Map<String, String> attributes = new TreeMap<>();

        if (entry instanceof KeyStore.PrivateKeyEntry pke) {
            Certificate[] chain = pke.getCertificateChain();
            if (chain != null) {
                certChain = new ArrayList<>(chain.length);
                for (Certificate cert : chain) {
                    certChain.add(cert.getEncoded());
                }
            }

            PrivateKey pk = pke.getPrivateKey();
            if (pk != null) {
                key = pk.getEncoded();
            }

            for (var attr : pke.getAttributes()) {
                attributes.put(attr.getName(), attr.getValue());
            }

        } else if (entry instanceof KeyStore.TrustedCertificateEntry tce) {
            trustedCert = tce.getTrustedCertificate().getEncoded();

            for (var attr : tce.getAttributes()) {
                attributes.put(attr.getName(), attr.getValue());
            }

        } else if (entry instanceof KeyStore.SecretKeyEntry ske) {
            SecretKey sk = ske.getSecretKey();
            if (sk != null) {
                key = sk.getEncoded();
            }

            for (var attr : ske.getAttributes()) {
                attributes.put(attr.getName(), attr.getValue());
            }
        }

        return new CanonicalEntry(alias, entry.getClass().getSimpleName(), certChain, trustedCert, key, attributes);
    }
}
