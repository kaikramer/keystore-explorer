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

package org.kse.gui.actions;

import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewCertificate;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to display details about selected certificates
 */
public class SelectedCertificatesChainDetailsAction extends KeyStoreExplorerAction {

    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public SelectedCertificatesChainDetailsAction(KseFrame kseFrame) {
        super(kseFrame);
        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0));
        putValue(LONG_DESCRIPTION, res.getString("SelectedCertificatesChainDetailsAction.statusbar"));
        putValue(NAME, res.getString("SelectedCertificatesChainDetailsAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("SelectedCertificatesChainDetailsAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/certdetails.png"))));
    }

    @Override
    protected void doAction() {
        showCertificatesSelectedEntries();
    }

    /**
     * Show the certificates details of the multiple selected KeyStore entries.
     */
    public void showCertificatesSelectedEntries() {
        Set<X509Certificate> setCertificates = getCertificates();
        X509Certificate[] certs = setCertificates.toArray(X509Certificate[]::new);
        DViewCertificate dViewCertificate;
        try {
            dViewCertificate = new DViewCertificate(frame, MessageFormat.format(
                    res.getString("SelectedCertificatesChainDetailsAction.CertDetailsEntry.Title"), ""), certs,
                    kseFrame, DViewCertificate.EXPORT);
            dViewCertificate.setLocationRelativeTo(frame);
            dViewCertificate.setVisible(true);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private Set<X509Certificate> getCertificates() {
        KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
        KeyStoreState currentState = history.getCurrentState();

        String[] aliases = kseFrame.getSelectedEntryAliases();
        try {
            Set<X509Certificate> setCertificates = new HashSet<>();
            KseKeyStore keyStore = currentState.getKeyStore();
            for (String alias : aliases) {
                if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
                    Certificate certificate = keyStore.getCertificate(alias);
                    setCertificates.add((X509Certificate) certificate);
                } else if (KeyStoreUtil.isKeyPairEntry(alias, keyStore)) {
                    Certificate[] chain = keyStore.getCertificateChain(alias);
                    if (chain != null) {
                        for (Certificate certificate : chain) {
                            setCertificates.add((X509Certificate) certificate);
                        }
                    }
                }
            }
            return setCertificates;
        } catch (Exception ex) {
            DError.displayError(frame, ex);
            return Collections.emptySet();
        }
    }
}
