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

package org.kse.gui.dialogs.sign;

import java.io.File;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.kse.crypto.digest.DigestType;
import org.kse.crypto.signing.JarSigner;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.dialogs.JWaitDialog;
import org.kse.gui.error.DError;

/**
 * <h1>Jar Signing</h1> The class initiates jar signing.
 * <p>
 * The user may cancel at any time by pressing the cancel button.
 */
public class DSignJarSigning extends JWaitDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

    private Map<String, String> fileExceptions;
    private File[] inputJarFiles;
    private List<File> outputJarFiles;
    private PrivateKey privateKey;
    private X509Certificate[] certs;
    private SignatureType signatureType;
    private String signatureName;
    private String signer;
    private DigestType digestType;
    private String tsaUrl;
    private Provider provider;

    /**
     * Creates a new DSignJarSigning dialog.
     *
     * @param parent         The parent frame
     * @param inputJarFiles  Array of jar files to be signed.
     * @param outputJarFiles Array of output jar files for writing the signature. Must match 1:1
     *                          with the inputJarFiles. The names can be identical to the inputJarFile names.
     * @param privateKey     The private key for signing the jars.
     * @param certs          The certificate chain associated with the private key.
     * @param signatureType  The signature algorithm to use for signing.
     * @param signatureName  The signature name for the signature block file name.
     * @param signer         The signer name for the jar file manifest.
     * @param digestType     The message digest algorithm to use for hashing.
     * @param tsaUrl         The time stamp authority URL for the time stamp counter signature (optional).
     * @param provider       The security provider to use.
     */
    public DSignJarSigning(JFrame parent, File[] inputJarFiles, List<File> outputJarFiles, PrivateKey privateKey,
                           X509Certificate[] certs, SignatureType signatureType, String signatureName, String signer,
                           DigestType digestType, String tsaUrl, Provider provider) {
        super(parent, res.getString("DSignJarSigning.Title"), res.getString("DSignJarSigning.jlSignJar.text"), null,
                res.getString("DSignJarSigning.jbCancel.text"));
        this.inputJarFiles = inputJarFiles;
        this.outputJarFiles = outputJarFiles;
        this.privateKey = privateKey;
        this.certs = certs;
        this.signatureType = signatureType;
        this.signatureName = signatureName;
        this.signer = signer;
        this.digestType = digestType;
        this.tsaUrl = tsaUrl;
        this.provider = provider;
        initProgressBar(0, inputJarFiles.length);
    }

    /**
     * Start signing in a separate thread.
     */
    public void startDSignJarSigning() {
        startTask(new SignJars());
    }

    /**
     * Get the generated errors during signing.
     *
     * @return Map of the generated signing errors.
     */
    public Map<String, String> getFileExceptions() {
        return fileExceptions;

    }

    /**
     * Generates the Jar signing
     * <p>
     * Signs the jars.
     * <p>
     * Errors generated during the signing are set to the map.
     */
    private class SignJars implements Runnable {
        @Override
        public void run() {
            try {
                // set new hashmap
                fileExceptions = new HashMap<>();
                for (int i = 0; i < inputJarFiles.length; i++) {
                    try {
                        if (inputJarFiles[i].equals(outputJarFiles.get(i))) {
                            JarSigner.sign(inputJarFiles[i], privateKey, certs, signatureType, signatureName, signer,
                                           digestType, tsaUrl, provider);
                        } else {
                            JarSigner.sign(inputJarFiles[i], outputJarFiles.get(i), privateKey, certs, signatureType,
                                           signatureName, signer, digestType, tsaUrl, provider);
                        }
                    }
                    // Add any jar sign exceptions to the map
                    catch (Exception e) {
                        fileExceptions.put(inputJarFiles[i].getName(), e.toString());
                    }
                    updateProgress(i);
                }

                SwingUtilities.invokeLater(() -> {
                    if (DSignJarSigning.this.isShowing()) {
                        closeDialog();
                    }
                });
            } catch (final Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (DSignJarSigning.this.isShowing()) {
                        DError dError = new DError(DSignJarSigning.this, ex);
                        dError.setLocationRelativeTo(DSignJarSigning.this);
                        dError.setVisible(true);
                        closeDialog();
                    }
                });
            }
        }
    }
}
