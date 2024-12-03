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
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.kse.KSE;
import org.kse.gui.passwordmanager.Password;
import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.sign.DSignFile;
import org.kse.gui.dialogs.sign.DSignJarSigning;
import org.kse.gui.error.DError;
import org.kse.gui.error.DErrorCollection;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to sign a JAR using the selected key pair entry.
 */
public class SignFileAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 6227240459189308322L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public SignFileAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(LONG_DESCRIPTION, res.getString("SignFileAction.statusbar"));
        putValue(NAME, res.getString("SignFileAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("SignFileAction.tooltip"));
        // TODO JW - Need icon for sign file.
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/signjar.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStoreState currentState = history.getCurrentState();

            String alias = kseFrame.getSelectedEntryAlias();

            Password password = getEntryPassword(alias, currentState);

            if (password == null) {
                return;
            }

            // set the keystore state
            KeyStore keyStore = currentState.getKeyStore();

            // set the provider history
            Provider provider = history.getExplicitProvider();

            // set the private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

            // set the certificate
            X509Certificate[] certs = X509CertUtil.orderX509CertChain(
                    X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias)));

            // set the key pair type
            KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);

            // get the jars, signatures, and time stamp
            DSignFile dSignFile = new DSignFile(frame, privateKey, keyPairType, alias);
            dSignFile.setLocationRelativeTo(frame);
            dSignFile.setVisible(true);

            // check if jar sign dialog was successful
            if (!dSignFile.isSuccessful()) {
                return;
            }

            // TODO JW - When using RSA and MFG1, the MFG1 is not displayed when viewing the signature.
            boolean detachedSignature = dSignFile.isDetachedSignature();
            SignatureType signatureType = dSignFile.getSignatureType();
            File inputFile = dSignFile.getInputFile();
            File outputFile = dSignFile.getOutputFile();
            String tsaUrl = dSignFile.getTimestampingServerUrl();

            // TODO JW - What if the dialog is cancelled?
            sign(inputFile, outputFile, privateKey, certs, detachedSignature, signatureType, tsaUrl, provider);

            // start jar signing process
//            DSignJarSigning dSignJarSigning = new DSignJarSigning(frame, inputJarFile, outputJarFile, privateKey, certs,
//                                                                  signatureType, signatureName, signer, digestType,
//                                                                  tsaUrl, provider);
//            dSignJarSigning.setLocationRelativeTo(frame);
//            dSignJarSigning.startDSignJarSigning();
//            dSignJarSigning.setVisible(true);
//
//            // check if jar signing was successful
//            if (!dSignJarSigning.isSuccessful()) {
//                return;
//            }
//
//            // check if exceptions were caught during jar signing
//            if (!dSignJarSigning.getFileExceptions().isEmpty()) {
//                Integer fileCount = inputJarFile.length;
//                Integer errorCount = dSignJarSigning.getFileExceptions().size();
//                String message = MessageFormat.format(res.getString("SignJarAction.SignJarError.message"),
//                                                      errorCount,
//                                                      fileCount);
//
//                String viewButtonText = res.getString("SignJarAction.ButtonView.message");
//                String okButtonText = res.getString("SignJarAction.ButtonOK.message");
//                Object[] buttonTexts = { viewButtonText, okButtonText };
//
//                int selected = JOptionPane.showOptionDialog(frame, message,
//                                                            res.getString("SignJarAction.SignJar.Title"),
//                                                            JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE,
//                                                            null, buttonTexts, okButtonText);
//
//                // if view button pressed show error collection
//                if (selected == 0) {
//                    DErrorCollection dError = new DErrorCollection(frame, dSignJarSigning.getFileExceptions());
//                    dError.setVisible(true);
//                }
//            } else {
//                Integer fileCount = inputJarFile.length;
//                String message = MessageFormat.format(res.getString("SignJarAction.SignJarSuccessful.message"),
//                                                      fileCount);
//                JOptionPane.showMessageDialog(frame, message, res.getString("SignJarAction.SignJar.Title"),
//                                              JOptionPane.INFORMATION_MESSAGE);
//            }

        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    public static void sign(File inputFile, File outputFile, PrivateKey privateKey, X509Certificate[] certificateChain,
            boolean detachedSignature, SignatureType signatureType, String tsaUrl, Provider provider)
            throws CryptoException {
        try {
            CMSTypedData msg = new CMSProcessableFile(inputFile);

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureType.jce()).build(privateKey);
            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                            .build(contentSigner, certificateChain[0]));
            generator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

            CMSSignedData sig = generator.generate(msg, !detachedSignature);

            try (OutputStream os = new FileOutputStream(outputFile)) {
                os.write(sig.getEncoded());
            }
        }
        catch (Exception e) {
            // TODO JW - Create exception message
            throw new CryptoException("TODO");
        }
    }
}
