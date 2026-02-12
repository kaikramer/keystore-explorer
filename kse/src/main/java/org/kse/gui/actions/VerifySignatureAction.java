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
import java.awt.event.InputEvent;
import java.io.File;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.kse.crypto.CryptoException;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.signing.CmsUtil;
import org.kse.crypto.signing.KseSignerInformation;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewSignature;
import org.kse.gui.error.DError;

/**
 * Action to verify a PKCS #7 / CMS digital signature.
 */
public class VerifySignatureAction extends AuthorityCertificatesVerifyAction {
    private static final long serialVersionUID = 1L;

    /**
     *
     * @param kseFrame KeyStore Explorer frame
     */
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
            File signatureFile = chooseSignatureFile();
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

            @SuppressWarnings("unchecked")
            Store<X509CertificateHolder> trustedCerts = new JcaCertStore(getTrustedCertificates());

            SignerInformationStore signerInfos = signedData.getSignerInfos();
            List<KseSignerInformation> signers = CmsUtil.convertSignerInformations(signerInfos.getSigners(),
                    trustedCerts, signedData);

            DViewSignature dViewSignature = new DViewSignature(frame, MessageFormat
                    .format(res.getString("VerifySignatureAction.SignatureDetailsFile.Title"), signatureFile.getName()),
                    signers, getTrustedCertsNoPrefs(), kseFrame);
            dViewSignature.setLocationRelativeTo(frame);
            dViewSignature.setVisible(true);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    /*
     * This method checks for the presence of a certificate chain or certificate
     * rather than checking the key store entry type to allow signers to verify
     * that their PKCS#7/CMS signature is trusted by using their signing key store.
     */
    @Override
    protected Collection<X509Certificate> extractCertificates(KseKeyStore keystore) throws CryptoException {

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
