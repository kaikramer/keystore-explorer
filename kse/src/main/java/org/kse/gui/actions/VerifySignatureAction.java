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
import java.awt.event.InputEvent;
import java.io.File;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.kse.AuthorityCertificates;
import org.kse.crypto.CryptoException;
import org.kse.crypto.SecurityProvider;
import org.kse.crypto.signing.CmsUtil;
import org.kse.crypto.signing.KseSignerInformation;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewSignature;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

public class VerifySignatureAction extends AuthorityCertificatesAction {
    private static final long serialVersionUID = 1L;

    public VerifySignatureAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('V',
                Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() + InputEvent.ALT_DOWN_MASK));
        putValue(LONG_DESCRIPTION, res.getString("VerifySignatureAction.statusbar"));
        putValue(NAME, res.getString("VerifySignatureAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("VerifySignatureAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/verifysignature.png"))));
    }

    @Override
    protected void doAction() {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

            KeyStoreState currentState = history.getCurrentState();
            KeyStore keyStore = currentState.getKeyStore();

            File signatureFile = showFileSelectionDialog();
            if (signatureFile == null) {
                return;
            }

            CMSSignedData signedData = CmsUtil.loadSignature(signatureFile, this::chooseContentFile);
            if (signedData.isCertificateManagementMessage()) {
                JOptionPane.showMessageDialog(frame,
                        MessageFormat.format(res.getString("VerifySignatureAction.NoSignatures.message"),
                                signatureFile.getName()),
                        res.getString("VerifySignatureAction.VerifySignature.Title"), JOptionPane.INFORMATION_MESSAGE);

                return;
            }

            KeyStore caCertificates = getCaCertificates();
            KeyStore windowsTrustedRootCertificates = getWindowsTrustedRootCertificates();

            // Perform cert lookup against current KeyStore
            Set<X509Certificate> compCerts = new HashSet<>();
            compCerts.addAll(extractCertificates(keyStore));

            if (caCertificates != null) {
                // Perform cert lookup against CA Certificates KeyStore
                compCerts.addAll(extractCertificates(caCertificates));
            }

            if (windowsTrustedRootCertificates != null) {
                // Perform cert lookup against Windows Trusted Root Certificates KeyStore
                compCerts.addAll(extractCertificates(windowsTrustedRootCertificates));
            }

            @SuppressWarnings("unchecked")
            Store<X509CertificateHolder> trustedCerts = new JcaCertStore(compCerts);

            SignerInformationStore signerInfos = signedData.getSignerInfos();
            List<KseSignerInformation> signers = CmsUtil.convertSignerInformations(signerInfos.getSigners(),
                    trustedCerts, signedData.getCertificates());

            DViewSignature dViewSignature = new DViewSignature(frame, MessageFormat
                    .format(res.getString("VerifySignatureAction.SignatureDetailsFile.Title"), signatureFile.getName()),
                    signedData, signers, getTrustedCertsNoPrefs(), null);
            dViewSignature.setLocationRelativeTo(frame);
            dViewSignature.setVisible(true);

            kseFrame.updateControls(true);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private Collection<X509Certificate> extractCertificates(KeyStore keystore) throws CryptoException {

        List<X509Certificate> certs = new ArrayList<>();

        try {
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                Certificate[] certChain = keystore.getCertificateChain(alias);
                if (certChain != null) {
                    for (Certificate cert : certChain) {
                        certs.add(X509CertUtil.convertCertificate(cert));
                    }
                }

                Certificate cert = keystore.getCertificate(alias);
                if (cert != null) {
                    certs.add(X509CertUtil.convertCertificate(cert));
                }
            }
        }
        catch (KeyStoreException e) {
            throw new CryptoException(res.getString("VerifySignatureAction.NoExtractCertificates.message"), e);
        }

        return certs;
    }

    private Store<X509CertificateHolder> getTrustedCertsNoPrefs()
            throws CryptoException, CertificateEncodingException {
        KeyStore caCertificates = getCaCertificatesNoPrefCheck();
        KeyStore windowsTrustedRootCertificates = getWindowsTrustedRootCertificatesNoPrefCheck();

        // Perform cert lookup against current KeyStore
        Set<X509Certificate> compCerts = new HashSet<>();

        if (caCertificates != null) {
            // Perform cert lookup against CA Certificates KeyStore
            compCerts.addAll(extractCertificates(caCertificates));
        }

        if (windowsTrustedRootCertificates != null) {
            // Perform cert lookup against Windows Trusted Root Certificates KeyStore
            compCerts.addAll(extractCertificates(windowsTrustedRootCertificates));
        }

        @SuppressWarnings("unchecked")
        Store<X509CertificateHolder> trustedCerts = new JcaCertStore(compCerts);
        return trustedCerts;
    }

    /**
     * Get CA Certificates KeyStore.
     *
     * @return KeyStore or null if unavailable
     */
    private KeyStore getCaCertificatesNoPrefCheck() {
        AuthorityCertificates authorityCertificates = AuthorityCertificates.getInstance();

        KeyStore caCertificates = authorityCertificates.getCaCertificates();

        if (caCertificates == null) {
            caCertificates = loadCaCertificatesKeyStore();

            if (caCertificates != null) {
                authorityCertificates.setCaCertificates(caCertificates);
            }
        }

        return caCertificates;
    }

    /**
     * Get Windows Trusted Root Certificates KeyStore.
     *
     * @return KeyStore or null if unavailable
     * @throws CryptoException If a problem occurred getting the KeyStore
     */
    private KeyStore getWindowsTrustedRootCertificatesNoPrefCheck() throws CryptoException {
        AuthorityCertificates authorityCertificates = AuthorityCertificates.getInstance();

        KeyStore windowsTrustedRootCertificates = null;

        if (Security.getProvider(SecurityProvider.MS_CAPI.jce()) != null) {
            windowsTrustedRootCertificates = authorityCertificates.getWindowsTrustedRootCertificates();
        }

        return windowsTrustedRootCertificates;
    }

    private File showFileSelectionDialog() {
        File signatureFile = chooseSignatureFile();
        if (signatureFile == null) {
            return null;
        }

        return signatureFile;
    }

    private File chooseSignatureFile() {
        JFileChooser chooser = FileChooserFactory.getSignatureFileChooser();
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setDialogTitle(res.getString("VerifySignatureAction.ChooseSignature.Title"));
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("VerifySignatureAction.ChooseSignature.button"));

        int rtnValue = chooser.showOpenDialog(frame);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File importFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(importFile);
            return importFile;
        }
        return null;
    }

    private File chooseContentFile() {
        JFileChooser chooser = FileChooserFactory.getNoFileChooser();
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setDialogTitle(res.getString("VerifySignatureAction.ChooseContent.Title"));
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("VerifySignatureAction.ChooseContent.button"));

        int rtnValue = chooser.showOpenDialog(frame);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File importFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(importFile);
            return importFile;
        }
        return null;
    }
}
