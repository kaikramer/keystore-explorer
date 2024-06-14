package org.kse.gui.actions;

import java.awt.Toolkit;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.importexport.DExportCertificates;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;
import org.kse.utilities.io.FileNameUtil;

/**
 * Action to export selected certificates.
 */
public class ExportSelectedCertificatesAction extends KeyStoreExplorerAction {

    private static final long serialVersionUID = 1L;

    public ExportSelectedCertificatesAction(KseFrame kseFrame) {
        super(kseFrame);
        putValue(LONG_DESCRIPTION, res.getString("ExportSelectedCertificatesAction.statusbar"));
        putValue(NAME, res.getString("ExportSelectedCertificatesAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("ExportSelectedCertificatesAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/exportselectedcerts.png"))));
    }

    @Override
    protected void doAction() {
        List<X509Certificate> listCertificate = getCertificates();
        File exportFile = null;
        try {
            if (!listCertificate.isEmpty()) {
                KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
                String fileName = FileNameUtil.removeExtension(history.getName());
                DExportCertificates dExportCertificates = new DExportCertificates(frame, fileName, false, true);
                dExportCertificates.setLocationRelativeTo(frame);
                dExportCertificates.setVisible(true);

                if (!dExportCertificates.exportSelected()) {
                    return;
                }
                X509Certificate[] certs = listCertificate.toArray(new X509Certificate[0]);
                certs = X509CertUtil.orderX509CertsChain(certs);
                exportFile = dExportCertificates.getExportFile();

                boolean pemEncode = dExportCertificates.pemEncode();

                byte[] encoded = null;

                if (dExportCertificates.exportFormatX509()) {
                    encoded = X509CertUtil.getCertsEncodedX509Pem(certs).getBytes();
                } else if (dExportCertificates.exportFormatPkcs7()) {
                    if (pemEncode) {
                        encoded = X509CertUtil.getCertsEncodedPkcs7Pem(certs).getBytes();
                    } else {
                        encoded = X509CertUtil.getCertsEncodedPkcs7(certs);
                    }
                } else if (dExportCertificates.exportFormatPkiPath()) {
                    encoded = X509CertUtil.getCertsEncodedPkiPath(certs);
                } else if (dExportCertificates.exportFormatSpc()) {
                    encoded = X509CertUtil.getCertsEncodedPkcs7(certs); // SPC is just DER PKCS #7
                }
                exportEncodedCertificate(encoded, exportFile);
                JOptionPane.showMessageDialog(frame,
                        res.getString("ExportSelectedCertificatesAction.ExportCertificateSuccessful.message"),
                        res.getString("ExportSelectedCertificatesAction.ExportCertificate.Title"),
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(frame, res.getString("ExportSelectedCertificatesAction.onemore.message"),
                        res.getString("ExportSelectedCertificatesAction.ExportCertificate.Title"),
                        JOptionPane.WARNING_MESSAGE);
            }
        } catch (FileNotFoundException ex) {
            String message = MessageFormat.format(res.getString("ExportSelectedCertificatesAction.NoWriteFile.message"),
                    exportFile);

            JOptionPane.showMessageDialog(frame, message,
                    res.getString("ExportSelectedCertificatesAction.ExportCertificate.Title"),
                    JOptionPane.WARNING_MESSAGE);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private List<X509Certificate> getCertificates() {
        KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
        KeyStoreState currentState = history.getCurrentState();

        String[] aliases = kseFrame.getSelectedEntryAliases();
        try {
            List<X509Certificate> listCertificates = new ArrayList<>();
            KeyStore keyStore = currentState.getKeyStore();
            for (String alias : aliases) {
                if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
                    Certificate certificate = keyStore.getCertificate(alias);
                    listCertificates.add((X509Certificate) certificate);
                } else if (KeyStoreUtil.isKeyPairEntry(alias, keyStore)) {
                    Certificate[] chain = keyStore.getCertificateChain(alias);
                    if (chain != null) {
                        for (Certificate certificate : chain) {
                            listCertificates.add((X509Certificate) certificate);
                        }
                    }
                }
            }
            return listCertificates;
        } catch (Exception ex) {
            DError.displayError(frame, ex);
            return Collections.emptyList();
        }
    }

    private void exportEncodedCertificate(byte[] encoded, File exportFile) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(exportFile)) {
            fos.write(encoded);
            fos.flush();
        }
    }
}
