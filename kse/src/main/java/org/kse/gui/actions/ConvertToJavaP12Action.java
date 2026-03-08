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

import javax.swing.JOptionPane;

import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.keystore.Pkcs12KeyStoreAdapter;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.StringUtils;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreState;

/**
 * This is a pseudo-action (no UI) that will prompt the user to convert a PKCS #12 file
 * to a Java supported version by converting any invisible certificates into Java trusted
 * certificates. This action implements HistoryAction so that it supports undo/redo.
 */
public class ConvertToJavaP12Action extends KeyStoreExplorerAction implements HistoryAction {

    private static final long serialVersionUID = 1L;

    private Pkcs12KeyStoreAdapter openedKeyStore;
    private KeyStoreState currentState;

    /**
     * Construct action.
     *
     * @param kseFrame       KeyStore Explorer frame
     * @param openedKeyStore The PKCS12 key store.
     * @param currentState   The current key store state.
     */
    public ConvertToJavaP12Action(KseFrame kseFrame, Pkcs12KeyStoreAdapter openedKeyStore, KeyStoreState currentState) {
        super(kseFrame);
        this.openedKeyStore = openedKeyStore;
        this.currentState = currentState;

        putValue(NAME, res.getString("ConvertToJavaP12Action.text"));
    }

    @Override
    public String getHistoryDescription() {
        return (String) getValue(NAME);
    }

    @Override
    protected void doAction() {
        try {
            if (openedKeyStore.hasInvisibleCerts()) {
                int selection = JOptionPane.showConfirmDialog(frame,
                        res.getString("ConvertToJavaP12Action.ConvertKeyStore.message"),
                        res.getString("ConvertToJavaP12Action.ConvertKeyStore.Title"), JOptionPane.YES_NO_OPTION,
                        JOptionPane.INFORMATION_MESSAGE);
                if (selection == JOptionPane.YES_OPTION) {
                    KeyStoreState newState = currentState.createBasisForNextState(this);

                    KseKeyStore newKeyStore = newState.getKeyStore();

                    int index = 1;
                    for (Pkcs12KeyStoreAdapter.CertEntry certEntry : openedKeyStore.getInvisibleCerts()) {
                        String alias = certEntry.alias();
                        if (StringUtils.isBlank(alias)) {
                            alias = X509CertUtil.getCertificateAlias(X509CertUtil.convertCertificate(certEntry.cert()));
                            if (alias.isBlank()) {
                                alias = "cert";
                            }
                        }
                        String proposedAlias = alias;
                        while (newKeyStore.containsAlias(proposedAlias)) {
                            proposedAlias = alias + index++;
                        }
                        newKeyStore.setCertificateEntry(alias, certEntry.cert());
                    }

                    currentState.append(newState);
                }
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

}
