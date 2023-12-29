package org.kse.gui.actions;

import java.awt.Toolkit;
import java.awt.event.InputEvent;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreUtil;
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
        putValue(ACCELERATOR_KEY,
                 KeyStroke.getKeyStroke(res.getString("CompareCertificateAction.accelerator").charAt(0),
                                        Toolkit.getDefaultToolkit().getMenuShortcutKeyMask() + InputEvent.ALT_MASK));
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
            KeyStore keyStore = currentState.getKeyStore();
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
