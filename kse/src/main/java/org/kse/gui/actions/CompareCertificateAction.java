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
import java.awt.event.InputEvent;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DCompareCertificates;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to show Compare Certificate dialog.
 */
public class CompareCertificateAction extends KeyStoreExplorerAction {

    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public CompareCertificateAction(KseFrame kseFrame) {
        super(kseFrame);
        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('C', Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() +
                                                              InputEvent.ALT_DOWN_MASK));
        putValue(LONG_DESCRIPTION, res.getString("CompareCertificateAction.statusbar"));
        putValue(NAME, res.getString("CompareCertificateAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("CompareCertificateAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/comparecerts.png"))));
    }

    @Override
    protected void doAction() {
        List<Certificate> listCertificate = getCertificates();
        if (listCertificate != null && listCertificate.size() == 2) {
            X509Certificate cert1 = (X509Certificate) listCertificate.get(0);
            X509Certificate cert2 = (X509Certificate) listCertificate.get(1);
            DCompareCertificates dialog = new DCompareCertificates(frame, cert1, cert2);
            dialog.setLocationRelativeTo(null);
            dialog.setVisible(true);
        } else {
            JOptionPane.showMessageDialog(frame, res.getString("CompareCertificateAction.onlytwo.message"),
                                          res.getString("CompareCertificateAction.Title"), JOptionPane.WARNING_MESSAGE);
        }
    }

    private List<Certificate> getCertificates() {
        KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
        KeyStoreState currentState = history.getCurrentState();

        String[] aliases = kseFrame.getSelectedEntryAliases();

        if (aliases.length < 2) {
            return null;
        }
        try {
            List<Certificate> listCertificates = new ArrayList<>();
            KseKeyStore keyStore = currentState.getKeyStore();
            for (String alias : aliases) {
                if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore) ||
                    KeyStoreUtil.isKeyPairEntry(alias, keyStore)) {
                    Certificate certificate = keyStore.getCertificate(alias);
                    listCertificates.add(certificate);
                }
            }
            return listCertificates;
        } catch (Exception ex) {
            DError.displayError(frame, ex);
            return null;
        }
    }

}
