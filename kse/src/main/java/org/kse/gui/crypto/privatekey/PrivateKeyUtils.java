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
 *
 */

package org.kse.gui.crypto.privatekey;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import org.kse.crypto.CryptoException;
import org.kse.crypto.jwk.JwkUtil;
import org.kse.crypto.privatekey.MsPvkUtil;
import org.kse.crypto.privatekey.OpenSslPbeType;
import org.kse.crypto.privatekey.OpenSslPvkUtil;
import org.kse.crypto.privatekey.Pkcs8PbeType;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyJwk;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyOpenSsl;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyPkcs8;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyPvk;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.preferences.data.KsePreferences;

import com.nimbusds.jose.JWEAlgorithm;

/**
 * Utilities for exporting private keys.
 */
public class PrivateKeyUtils {

    /**
     * Export a private key to format pkcs8
     *
     * @param privateKey          Private key
     * @param alias               Name of alias or file name
     * @param frame               The parent frame
     * @param preferences         Password quality configuration
     * @param res                 ResourceBundle
     * @throws CryptoException    thrown on error during encryption
     * @throws IOException        thrown on I/O error when writing the file
     */
    public static void exportAsPkcs8(PrivateKey privateKey, String alias, JFrame frame,
                                     KsePreferences preferences, ResourceBundle res)
            throws CryptoException, IOException {
        File exportFile = null;

        try {
            DExportPrivateKeyPkcs8 dExportPrivateKeyPkcs8 =
                    new DExportPrivateKeyPkcs8(frame, alias, preferences.getPasswordQualityConfig());
            dExportPrivateKeyPkcs8.setLocationRelativeTo(frame);
            dExportPrivateKeyPkcs8.setVisible(true);

            if (!dExportPrivateKeyPkcs8.exportSelected()) {
                return;
            }

            exportFile = dExportPrivateKeyPkcs8.getExportFile();
            boolean pemEncode = dExportPrivateKeyPkcs8.pemEncode();
            boolean encrypt = dExportPrivateKeyPkcs8.encrypt();

            Pkcs8PbeType pbeAlgorithm = null;
            Password exportPassword = null;

            if (encrypt) {
                pbeAlgorithm = dExportPrivateKeyPkcs8.getPbeAlgorithm();
                exportPassword = dExportPrivateKeyPkcs8.getExportPassword();
            }

            byte[] encoded = getPkcs8EncodedPrivateKey(privateKey, pemEncode, pbeAlgorithm, exportPassword);

            exportEncodedPrivateKey(encoded, exportFile);

            JOptionPane.showMessageDialog(frame, res.getString(
                                                  "ExportKeyPairPrivateKeyAction.ExportPrivateKeyPkcs8Successful" +
                                                  ".message"),
                                          res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPkcs8.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        } catch (FileNotFoundException | NoSuchFileException ex) {
            String message = MessageFormat.format(res.getString("ExportKeyPairPrivateKeyAction.NoWriteFile.message"),
                                                  exportFile);
            JOptionPane.showMessageDialog(frame, message,
                                          res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPkcs8.Title"),
                                          JOptionPane.WARNING_MESSAGE);
        }
    }

    private static byte[] getPkcs8EncodedPrivateKey(PrivateKey privateKey, boolean pemEncode, Pkcs8PbeType pbeAlgorithm,
                                                    Password password) throws CryptoException, IOException {
        byte[] encoded = null;

        if (pemEncode) {
            if ((pbeAlgorithm != null) && (password != null)) {
                encoded = Pkcs8Util.getEncryptedPem(privateKey, pbeAlgorithm, password).getBytes();
            } else {
                encoded = Pkcs8Util.getPem(privateKey).getBytes();
            }
        } else {
            if ((pbeAlgorithm != null) && (password != null)) {
                encoded = Pkcs8Util.getEncrypted(privateKey, pbeAlgorithm, password);
            } else {
                encoded = Pkcs8Util.get(privateKey);
            }
        }

        return encoded;
    }

    private static void exportEncodedPrivateKey(byte[] encoded, File exportFile) throws IOException {
        Files.write(exportFile.toPath(), encoded);
    }

    /**
     * Export a private key to format pvk
     *
     * @param privateKey            Private key
     * @param alias                 Name of alias or file name
     * @param frame                 The parent frame
     * @param preferences           Password quality configuration
     * @param res                   ResourceBundle
     * @throws CryptoException      thrown on error during encryption
     * @throws IOException          thrown on I/O error when writing the file
     */
    public static void exportAsPvk(PrivateKey privateKey, String alias, JFrame frame,
                                   KsePreferences preferences, ResourceBundle res)
            throws CryptoException, IOException {
        File exportFile = null;

        try {
            DExportPrivateKeyPvk dExportPrivateKeyPvk = new DExportPrivateKeyPvk(frame, alias, privateKey,
                                                                                 preferences.getPasswordQualityConfig());
            dExportPrivateKeyPvk.setLocationRelativeTo(frame);
            dExportPrivateKeyPvk.setVisible(true);

            if (!dExportPrivateKeyPvk.exportSelected()) {
                return;
            }

            exportFile = dExportPrivateKeyPvk.getExportFile();
            int keyType = dExportPrivateKeyPvk.getKeyType();
            boolean encrypt = dExportPrivateKeyPvk.encrypt();

            boolean strongEncryption = false;
            Password exportPassword = null;

            if (encrypt) {
                strongEncryption = dExportPrivateKeyPvk.useStrongEncryption();
                exportPassword = dExportPrivateKeyPvk.getExportPassword();
            }

            byte[] encoded = getPvkEncodedPrivateKey(privateKey, keyType, exportPassword, strongEncryption);

            exportEncodedPrivateKey(encoded, exportFile);

            JOptionPane.showMessageDialog(frame, res.getString(
                                                  "ExportKeyPairPrivateKeyAction.ExportPrivateKeyPvkSuccessful" +
                                                  ".message"),
                                          res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPvk.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        } catch (FileNotFoundException | NoSuchFileException ex) {
            String message = MessageFormat.format(res.getString("ExportKeyPairPrivateKeyAction.NoWriteFile.message"),
                                                  exportFile);
            JOptionPane.showMessageDialog(frame, message,
                                          res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPvk.Title"),
                                          JOptionPane.WARNING_MESSAGE);
        }
    }

    private static byte[] getPvkEncodedPrivateKey(PrivateKey privateKey, int keyType, Password password,
                                                  boolean strongEncryption) throws CryptoException {
        byte[] encoded = null;

        if (password != null) {
            if (privateKey instanceof RSAPrivateCrtKey) {
                encoded = MsPvkUtil.getEncrypted((RSAPrivateCrtKey) privateKey, keyType, password, strongEncryption);
            } else {
                encoded = MsPvkUtil.getEncrypted((DSAPrivateKey) privateKey, password, strongEncryption);
            }
        } else {
            if (privateKey instanceof RSAPrivateCrtKey) {
                encoded = MsPvkUtil.get((RSAPrivateCrtKey) privateKey, keyType);
            } else {
                encoded = MsPvkUtil.get((DSAPrivateKey) privateKey);
            }
        }

        return encoded;
    }

    /**
     * Export a private key to format openssl
     *
     * @param privateKey          Private key
     * @param alias               Name of alias or file name
     * @param frame               The parent frame
     * @param preferences         Password quality configuration
     * @param res                 ResourceBundle
     * @throws CryptoException    thrown on error during encryption
     * @throws IOException        thrown on I/O error when writing the file
     */
    public static void exportAsOpenSsl(PrivateKey privateKey, String alias, JFrame frame,
                                       KsePreferences preferences, ResourceBundle res)
            throws CryptoException, IOException {
        File exportFile = null;

        try {
            DExportPrivateKeyOpenSsl dExportPrivateKeyOpenSsl =
                    new DExportPrivateKeyOpenSsl(frame, alias, preferences.getPasswordQualityConfig());
            dExportPrivateKeyOpenSsl.setLocationRelativeTo(frame);
            dExportPrivateKeyOpenSsl.setVisible(true);

            if (!dExportPrivateKeyOpenSsl.exportSelected()) {
                return;
            }

            exportFile = dExportPrivateKeyOpenSsl.getExportFile();
            boolean pemEncode = dExportPrivateKeyOpenSsl.pemEncode();
            boolean encrypt = dExportPrivateKeyOpenSsl.encrypt();

            OpenSslPbeType pbeAlgorithm = null;
            Password exportPassword = null;

            if (encrypt) {
                pbeAlgorithm = dExportPrivateKeyOpenSsl.getPbeAlgorithm();
                exportPassword = dExportPrivateKeyOpenSsl.getExportPassword();
            }

            byte[] encoded = getOpenSslEncodedPrivateKey(privateKey, pemEncode, pbeAlgorithm, exportPassword);

            exportEncodedPrivateKey(encoded, exportFile);

            JOptionPane.showMessageDialog(frame, res.getString(
                                                  "ExportKeyPairPrivateKeyAction.ExportPrivateKeyOpenSslSuccessful" +
                                                  ".message"),
                                          res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyOpenSsl.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        } catch (FileNotFoundException | NoSuchFileException ex) {
            String message = MessageFormat.format(res.getString("ExportKeyPairPrivateKeyAction.NoWriteFile.message"),
                                                  exportFile);
            JOptionPane.showMessageDialog(frame, message,
                                          res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyOpenSsl.Title"),
                                          JOptionPane.WARNING_MESSAGE);
        }
    }

    private static byte[] getOpenSslEncodedPrivateKey(PrivateKey privateKey, boolean pemEncoded,
                                                      OpenSslPbeType pbeAlgorithm, Password password)
            throws CryptoException {
        byte[] encoded = null;

        if (pemEncoded) {
            if ((pbeAlgorithm != null) && (password != null)) {
                encoded = OpenSslPvkUtil.getEncrypted(privateKey, pbeAlgorithm, password).getBytes();
            } else {
                encoded = OpenSslPvkUtil.getPem(privateKey).getBytes();
            }
        } else {
            encoded = OpenSslPvkUtil.get(privateKey);
        }

        return encoded;
    }

    /** Exports supported {@link PrivateKey} instances as JWK
     *
     * @param privateKey instance of {@link PrivateKey} to be exported
     * @param alias private key alias; if not null, JWK exporter will use it as "kid" and a file name
     * @param frame The parent frame
     * @param preferences {@link KsePreferences} app configuration
     * @param res {@link ResourceBundle} instance with messages
     * @throws IOException thrown on I/O error when writing the file
     * @throws CryptoException thrown if JWK exporter fails on underlying JWK related code
     */
    public static void exportAsJwk(PrivateKey privateKey, String alias, JFrame frame,
                                   KsePreferences preferences, ResourceBundle res)
            throws CryptoException, IOException {
        File exportFile = null;
        try {
            DExportPrivateKeyJwk dExportPrivateKeyJwk =
                    new DExportPrivateKeyJwk(frame, alias, preferences.getPasswordQualityConfig());
            dExportPrivateKeyJwk.setLocationRelativeTo(frame);
            dExportPrivateKeyJwk.setVisible(true);

            if (!dExportPrivateKeyJwk.exportSelected()) {
                return;
            }

            exportFile = dExportPrivateKeyJwk.getExportFile();
            boolean compactFormat = dExportPrivateKeyJwk.compactFormat();
            boolean encrypt = dExportPrivateKeyJwk.encrypt();

            JWEAlgorithm jweAlgorithm = null;
            Password exportPassword = null;

            if (encrypt) {
                jweAlgorithm = dExportPrivateKeyJwk.getJweAlgorithm();
                exportPassword = dExportPrivateKeyJwk.getExportPassword();
            }

            String encoded;
            if (jweAlgorithm != null && exportPassword != null) {
                encoded = JwkUtil.get(privateKey, alias, jweAlgorithm, exportPassword, compactFormat);
            } else {
                encoded = JwkUtil.get(privateKey, alias);
            }

            exportEncodedPrivateKey(encoded.getBytes(StandardCharsets.UTF_8), exportFile);

            JOptionPane.showMessageDialog(
                    frame,
                    res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyJwkSuccessful.message"),
                    res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyJwk.Title"),
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (FileNotFoundException | NoSuchFileException ex) {
            String message = MessageFormat.format(res.getString("ExportKeyPairPrivateKeyAction.NoWriteFile.message"),
                    exportFile);
            JOptionPane.showMessageDialog(frame, message,
                    res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyJwk.Title"),
                    JOptionPane.WARNING_MESSAGE);
        }
    }
}
