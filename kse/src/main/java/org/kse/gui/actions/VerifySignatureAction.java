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

import java.awt.HeadlessException;
import java.awt.Toolkit;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.signing.CmsUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DGetAlias;
import org.kse.gui.dialogs.DVerifyCertificate;
import org.kse.gui.dialogs.DViewCertificate;
import org.kse.gui.dialogs.DViewSignature;
import org.kse.gui.dialogs.DVerifyCertificate.VerifyOptions;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.utilities.StringUtils;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

public class VerifySignatureAction extends AuthorityCertificatesAction {
    private static final long serialVersionUID = 1L;

    public VerifySignatureAction(KseFrame kseFrame) {
        super(kseFrame);

        // TODO JW - Add an accelerator?
//        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('K',
//                Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        // TODO JW - Need a good description.
        putValue(LONG_DESCRIPTION, res.getString("VerifySignatureAction.statusbar"));
        putValue(NAME, res.getString("VerifySignatureAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("VerifySignatureAction.tooltip"));
        // TODO JW - Need image for verify signature.
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/verifycert.png"))));
    }

    @Override
    protected void doAction() {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

            // TODO JW - Use cacerts truststore if no keystore is currently opened
            // handle case that no keystore is currently opened (-> create new keystore)
//            if (history == null) {
//                new NewAction(kseFrame).actionPerformed(null);
//                history = kseFrame.getActiveKeyStoreHistory();
//
//                // cancel pressed => abort
//                if (history == null) {
//                    return;
//                }
//            }

            // TODO JW - Remove these?
            KeyStoreState currentState = history.getCurrentState();
            KeyStore keyStore = currentState.getKeyStore();

            File signatureFile = showFileSelectionDialog();
            if (signatureFile == null) {
                return;
            }

            // TODO JW - What about the logic in openSignature?
            CMSSignedData signedData = CmsUtil.loadSignature(signatureFile, this::chooseContentFile);

            // TODO JW - Add new option for using cacerts for signature verification.
            if (preferences.getCaCertsSettings().isImportTrustedCertTrustCheckEnabled()) {
//                String matchAlias = X509CertUtil.matchCertificate(keyStore, trustCert);
//                if (matchAlias != null) {
//                    int selected = JOptionPane.showConfirmDialog(frame, MessageFormat.format(
//                                                                         res.getString(
//                                                                                 "ImportTrustedCertificateAction" +
//                                                                                 ".TrustCertExistsConfirm.message"),
//                                                                         matchAlias),
//                                                                 res.getString(
//                                                                         "ImportTrustedCertificateAction" +
//                                                                         ".ImportTrustCert.Title"),
//                                                                 JOptionPane.YES_NO_OPTION);
//                    if (selected != JOptionPane.YES_OPTION) {
//                        return;
//                    }
//                }

                KeyStore caCertificates = getCaCertificates();
                KeyStore windowsTrustedRootCertificates = getWindowsTrustedRootCertificates();

                // Establish against current KeyStore
                ArrayList<KeyStore> compKeyStores = new ArrayList<>();
                compKeyStores.add(keyStore);

                if (caCertificates != null) {
                    // Establish trust against CA Certificates KeyStore
                    compKeyStores.add(caCertificates);
                }

                if (windowsTrustedRootCertificates != null) {
                    // Establish trust against Windows Trusted Root Certificates KeyStore
                    compKeyStores.add(windowsTrustedRootCertificates);
                }

                // TODO JW - Verify the signature using the CA certs
                // TODO JW - Display dialog with option to see signature details.

                return;
            }

            // TODO JW - Verify the signature using the keystore
            // TODO JW build Store using certs from the truststore. If a cert cannot be found
            // then the signature should not be trusted (even if valid)
            boolean verified = false;
            Store<X509CertificateHolder> certStore = signedData.getCertificates();
            SignerInformationStore signers = signedData.getSignerInfos();
            for (SignerInformation signer : signers.getSigners()) {
//                AttributeTable signedAttributes = signer.getSignedAttributes();
//                AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
//
//                if (signedAttributes != null) {
//                    Hashtable ht = signedAttributes.toHashtable();
//                    for (Object k : ht.keySet()) {
//                        System.out.println(k + " :: " + ((Attribute) ht.get(k)).getAttrValues());
//                    }
//                }
//                if (unsignedAttributes != null) {
//                    Hashtable ht = unsignedAttributes.toHashtable();
//                    for (Object k : ht.keySet()) {
//                        System.out.println(k + " :: " + ((Attribute) ht.get(k)).getAttrValues());
//                    }
//                }
//
                // TODO JW - Should a provider be specified for the JcaSimpleSingerInfoVerifierBuilder?
                Collection<X509CertificateHolder> matchedCerts = certStore.getMatches(signer.getSID());
                if (!matchedCerts.isEmpty()) {
                    X509CertificateHolder cert = matchedCerts.iterator().next();
                    // TODO JW- Counter signing breaks the signature...
                    // TODO JW - this verifies using the attached certs. Need to link certs to keystore to validate the chain.
//                    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))) {
//                        System.out.println("Verified by: " + cert.getSubject());
//                        verified = true;
//
//                        TimeStampToken tspToken = CmsUtil.getTimeStampToken(signer);
//                        if (tspToken != null) {
//                            matchedCerts = tspToken.getCertificates().getMatches(tspToken.getSID());
//                            if (!matchedCerts.isEmpty()) {
//                                cert = matchedCerts.iterator().next();
//                                tspToken.validate(new JcaSimpleSignerInfoVerifierBuilder().build(cert));
//                                System.out.println("Time stamped by: " + cert.getSubject());
//                            }
//                        }
//                    }
                }
            }
            System.out.println("Verified: " + verified);

            DViewSignature dViewSignature = new DViewSignature(frame, MessageFormat
                    .format(res.getString("VerifySignatureAction.SignatureDetailsFile.Title"), signatureFile.getName()),
                    signedData, signedData.getSignerInfos().getSigners(), null);
            dViewSignature.setLocationRelativeTo(frame);
            dViewSignature.setVisible(true);

            /*
Signers:
    Signer's issuer DN: O=ICU Medical,CN=ICU Medical Dev Issuing
    Signer's serial: 30bc7fadef7fe924fa77a0f376f31d92b68fa33e
    Signing time: Mon Feb 07 23:07:19 UTC 2022
    Signature Algorithm: RSA-SHA256
    Signature Algorithm: RSA-PSS-SHA256           certtool shows SHA-256, but KSE shows SHA-384, which is what was used. (CmsSigner.java.p7m)
    Signed Attributes:
        messageDigest: 0420ed6b93a0a57ff71b075d7628f807db2d6f9a8727557a02b2f6f9ff520eb4caaf
        1.2.840.113549.1.9.52: 301c300b0609608648016503040201a10d06092a864886f70d01010b0500
        signingTime: 170d3232303230373233303731395a
        contentType: 06092a864886f70d010701
             */

            kseFrame.updateControls(true);

            JOptionPane.showMessageDialog(frame, res.getString(
                                                  "ImportTrustedCertificateAction.ImportTrustCertSuccessful.message"),
                                          res.getString("ImportTrustedCertificateAction.ImportTrustCert.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private boolean isCA(X509Certificate cert) {
        int basicConstraints = cert.getBasicConstraints();
        if (basicConstraints != -1) {
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage != null && keyUsage[5]) {
                return true;
            }
        }
        return false;
    }

    private KeyStore getKeyStore(KeyStoreHistory keyStoreHistory)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        KeyStore trustStore = null;
        trustStore = KeyStore.getInstance("JCEKS");
        trustStore.load(null, null);
        if (keyStoreHistory != null) {

            KeyStore tempTrustStore = keyStoreHistory.getCurrentState().getKeyStore();
            Enumeration<String> enumeration = tempTrustStore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                if (tempTrustStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class) ||
                    tempTrustStore.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
                    X509Certificate cert = (X509Certificate) tempTrustStore.getCertificate(alias);
                    if (isCA(cert)) {
                        trustStore.setCertificateEntry(alias, cert);
                    }
                }
            }
        }
        if (trustStore.size() == 0) {
//            if (keyCertChain != null) {
//                for (int i = 0; i < keyCertChain.length; i++) {
//                    X509Certificate cert = keyCertChain[i];
//                    if (isCA(cert)) {
//                        String entry = "entry" + i;
//                        trustStore.setCertificateEntry(entry, cert);
//                    }
//                }
//            }
        }
        return trustStore;
    }

    private X509Certificate getCertificate(String alias) throws CryptoException {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStore keyStore = history.getCurrentState().getKeyStore();

            return X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
        } catch (KeyStoreException ex) {
            String message = MessageFormat.format(res.getString("VerifySignatureAction.NoAccessEntry.message"),
                                                  alias);
            throw new CryptoException(message, ex);
        }
    }

    private X509Certificate[] getCertificateChain(String alias) throws CryptoException {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStore keyStore = history.getCurrentState().getKeyStore();
            X509Certificate[] certs = X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias));
            return certs;
        } catch (KeyStoreException ex) {
            String message = MessageFormat.format(res.getString("VerifySignatureAction.NoAccessEntry.message"),
                                                  alias);
            throw new CryptoException(message, ex);
        }
    }

    /**
     * Open a signature file.
     *
     * @param signatureFile The signature file
     * @return The signature found in the file or null if open failed
     */
    protected byte[] openSignature(File signatureFile) {
        try {
            return Files.readAllBytes(signatureFile.toPath());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(frame, MessageFormat.format(
                                                  res.getString("KeyStoreExplorerAction.NoReadFile.message"),
                                                  signatureFile),
                                          res.getString("KeyStoreExplorerAction.OpenSignature.Title"),
                                          JOptionPane.WARNING_MESSAGE);
            return null;
        }
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
