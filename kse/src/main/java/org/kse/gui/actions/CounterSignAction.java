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

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;

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
 * Action to counter sign a PKCS #7 signature using the selected key pair entry.
 */
public class CounterSignAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 6227240459189308322L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public CounterSignAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(LONG_DESCRIPTION, res.getString("CounterSignAction.statusbar"));
        putValue(NAME, res.getString("CounterSignAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("CounterSignAction.tooltip"));
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
            X509Certificate[] certs = X509CertUtil
                    .orderX509CertChain(X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias)));

            // set the key pair type
            KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);

            // get the file, signatures, and time stamp
            DSignFile dSignFile = new DSignFile(frame, privateKey, keyPairType, true);
            dSignFile.setLocationRelativeTo(frame);
            dSignFile.setVisible(true);

            // check if file sign dialog was successful
            if (!dSignFile.isSuccessful()) {
                return;
            }

            // TODO JW - When using RSA and MFG1, the MFG1 is not displayed when viewing the signature.
            boolean detachedSignature = dSignFile.isDetachedSignature();
            SignatureType signatureType = dSignFile.getSignatureType();
            File inputFile = dSignFile.getInputFile();
            File outputFile = dSignFile.getOutputFile();
            String tsaUrl = dSignFile.getTimestampingServerUrl();

            CMSSignedData signature = CmsUtil.loadSignature(inputFile, this::chooseContentFile);
            if (signature == null) {
                // TODO JW - identify the error conditions.
                return;
            }

            CMSSignedData signedData = CmsSigner.counterSign(signature, privateKey, certs, detachedSignature,
                    signatureType, tsaUrl, provider);

            try (OutputStream os = new FileOutputStream(outputFile)) {
                // TODO JW - What about generating a PEM encoded file?
                os.write(signedData.getEncoded());
            }

        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private File chooseContentFile() {
        JFileChooser chooser = FileChooserFactory.getNoFileChooser();
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setDialogTitle(res.getString("CounterSignAction.ChooseContent.Title"));
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("CounterSignAction.ChooseContent.button"));

        int rtnValue = chooser.showOpenDialog(frame);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File importFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(importFile);
            return importFile;
        }
        return null;
    }
}
