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

import java.awt.Toolkit;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DGetAlias;
import org.kse.gui.dialogs.importexport.DImportKeyPair;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to import a key pair.
 */
public class ImportKeyPairAction extends KeyStoreExplorerAction implements HistoryAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public ImportKeyPairAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('K',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        putValue(LONG_DESCRIPTION, res.getString("ImportKeyPairAction.statusbar"));
        putValue(NAME, res.getString("ImportKeyPairAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("ImportKeyPairAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/importkeypair.png"))));
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
        DImportKeyPair dImportKeyPair = new DImportKeyPair(frame);
        dImportKeyPair.setLocationRelativeTo(frame);
        dImportKeyPair.setVisible(true);

        try {
            PrivateKey privateKey = dImportKeyPair.getPrivateKey();
            X509Certificate[] certs = dImportKeyPair.getCertificateChain();

            if ((privateKey == null) || (certs == null)) {
                return;
            }

            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

            KeyStoreState currentState = history.getCurrentState();
            KeyStoreState newState = currentState.createBasisForNextState(this);

            KseKeyStore keyStore = newState.getKeyStore();
            KeyStoreType keyStoreType = KeyStoreType.resolveJce(keyStore.getType());

            DGetAlias dGetAlias = new DGetAlias(frame, res.getString("ImportKeyPairAction.NewKeyPairEntryAlias.Title"),
                                                X509CertUtil.getCertificateAlias(certs[0]));

            dGetAlias.setLocationRelativeTo(frame);
            dGetAlias.setVisible(true);
            String alias = keyStoreType.normalizeAlias(dGetAlias.getAlias());

            if (alias == null) {
                return;
            }

            if (keyStore.containsAlias(alias)) {
                String message = MessageFormat.format(res.getString("ImportKeyPairAction.OverWriteEntry.message"),
                                                      alias);

                int selected = JOptionPane.showConfirmDialog(frame, message, res.getString(
                        "ImportKeyPairAction.NewKeyPairEntryAlias.Title"), JOptionPane.YES_NO_OPTION);
                if (selected != JOptionPane.YES_OPTION) {
                    return;
                }
            }

            Password password = getNewEntryPassword(keyStoreType,
                    res.getString("ImportKeyPairAction.NewKeyPairEntryPassword.Title"), currentState, newState);
            if (password == null) {
                return;
            }

            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
                newState.removeEntryPassword(alias);
            }

            keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), certs);
            newState.setEntryPassword(alias, password);

            currentState.append(newState);

            kseFrame.updateControls(true);

            JOptionPane.showMessageDialog(frame, res.getString("ImportKeyPairAction.KeyPairImportSuccessful.message"),
                                          res.getString("ImportKeyPairAction.ImportKeyPair.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }
}
