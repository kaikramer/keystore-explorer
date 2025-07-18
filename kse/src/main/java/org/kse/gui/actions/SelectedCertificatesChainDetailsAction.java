package org.kse.gui.actions;

import java.awt.Toolkit;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.swing.ImageIcon;

import org.kse.crypto.keystore.KeyStoreUtil;
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
        putValue(LONG_DESCRIPTION, res.getString("SelectedCertificatesChainDetailsAction.statusbar"));
        putValue(NAME, res.getString("SelectedCertificatesChainDetailsAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("SelectedCertificatesChainDetailsAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/certdetails.png"))));
    }

    @Override
    protected void doAction() {
        Set<X509Certificate> setCertificates = getCertificates();
        X509Certificate[] certs = setCertificates.toArray(new X509Certificate[0]);
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
            KeyStore keyStore = currentState.getKeyStore();
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
