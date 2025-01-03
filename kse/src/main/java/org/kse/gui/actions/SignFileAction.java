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

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.bouncycastle.cms.CMSSignedData;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.CmsSigner;
import org.kse.crypto.signing.CmsUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.sign.DSignFile;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to sign a file using the selected key pair entry.
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
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/signfile.png"))));
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

            // get the file, signatures, and time stamp
            DSignFile dSignFile = new DSignFile(frame, privateKey, keyPairType);
            dSignFile.setLocationRelativeTo(frame);
            dSignFile.setVisible(true);

            // check if file sign dialog was successful
            if (!dSignFile.isSuccessful()) {
                return;
            }

            boolean detachedSignature = dSignFile.isDetachedSignature();
            SignatureType signatureType = dSignFile.getSignatureType();
            File inputFile = dSignFile.getInputFile();
            File outputFile = dSignFile.getOutputFile();
            String tsaUrl = dSignFile.getTimestampingServerUrl();

            CMSSignedData signedData;
            if (!dSignFile.isCounterSign()) {
                signedData = CmsSigner.sign(inputFile, privateKey, certs, detachedSignature, signatureType, tsaUrl,
                        provider);
            } else {
                CMSSignedData signature = CmsUtil.loadSignature(inputFile, this::chooseContentFile);

                if (signature.isCertificateManagementMessage()) {
                    JOptionPane.showMessageDialog(frame,
                            MessageFormat.format(res.getString("SignFileAction.NoSignatures.message"),
                                    inputFile.getName()),
                            res.getString("SignFileAction.CounterSign.Title"), JOptionPane.INFORMATION_MESSAGE);

                    return;
                }

                if (signature.getSignedContent() == null) {
                    // loadSignature tried to find and load the content but could not.
                    JOptionPane.showMessageDialog(frame,
                            MessageFormat.format(res.getString("SignFileAction.NoContent.message"),
                                    inputFile.getName()),
                            res.getString("SignFileAction.CounterSign.Title"), JOptionPane.ERROR_MESSAGE);

                    return;
                }

                signedData = CmsSigner.counterSign(signature, privateKey, certs, detachedSignature, signatureType,
                        tsaUrl, provider);
            }

            byte[] encoded;
            if (!dSignFile.isOutputPem()) {
                encoded = signedData.getEncoded();
            } else {
                encoded = CmsUtil.getPem(signedData).getBytes();
            }

            try (OutputStream os = new FileOutputStream(outputFile)) {
                os.write(encoded);
            }

        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private File chooseContentFile() {
        JFileChooser chooser = FileChooserFactory.getNoFileChooser();
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setDialogTitle(res.getString("SignFileAction.ChooseContent.Title"));
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("SignFileAction.ChooseContent.button"));

        int rtnValue = chooser.showOpenDialog(frame);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File importFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(importFile);
            return importFile;
        }
        return null;
    }
}
