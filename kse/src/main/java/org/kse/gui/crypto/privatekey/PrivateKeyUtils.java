package org.kse.gui.crypto.privatekey;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.privatekey.MsPvkUtil;
import org.kse.crypto.privatekey.OpenSslPbeType;
import org.kse.crypto.privatekey.OpenSslPvkUtil;
import org.kse.crypto.privatekey.Pkcs8PbeType;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyOpenSsl;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyPkcs8;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyPvk;
import org.kse.gui.preferences.ApplicationSettings;

public class PrivateKeyUtils {

    /**
     * Export a private key to format pkcs8
     *
     * @param privateKey          Private key
     * @param alias               Name of alias or file name
     * @param frame               The parent frame
     * @param applicationSettings Password quality configuration
     * @param res                 ResourceBundle
     * @throws CryptoException
     * @throws IOException
     */
    public static void exportAsPkcs8(PrivateKey privateKey, String alias, JFrame frame,
                                     ApplicationSettings applicationSettings, ResourceBundle res)
            throws CryptoException, IOException {
        File exportFile = null;

        try {
            DExportPrivateKeyPkcs8 dExportPrivateKeyPkcs8 =
                    new DExportPrivateKeyPkcs8(frame, alias, applicationSettings.getPasswordQualityConfig());
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
        } catch (FileNotFoundException ex) {
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
        try (FileOutputStream fos = new FileOutputStream(exportFile)) {
            fos.write(encoded);
            fos.flush();
        }
    }

    /**
     * Export a private key to format pvk
     *
     * @param privateKey            Private key
     * @param alias                 Name of alias or file name
     * @param frame                 The parent frame
     * @param applicationSettings   Password quality configuration
     * @param res                   ResourceBundle
     * @throws CryptoException
     * @throws IOException
     */
    public static void exportAsPvk(PrivateKey privateKey, String alias, JFrame frame,
                                   ApplicationSettings applicationSettings, ResourceBundle res)
            throws CryptoException, IOException {
        File exportFile = null;

        try {
            DExportPrivateKeyPvk dExportPrivateKeyPvk = new DExportPrivateKeyPvk(frame, alias, privateKey,
                                                                                 applicationSettings.getPasswordQualityConfig());
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
        } catch (FileNotFoundException ex) {
            String message = MessageFormat.format(res.getString("ExportKeyPairPrivateKeyAction.NoWriteFile.message"),
                                                  exportFile);
            JOptionPane.showMessageDialog(frame, message,
                                          res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPvk.Title"),
                                          JOptionPane.WARNING_MESSAGE);
        }
    }

    private static byte[] getPvkEncodedPrivateKey(PrivateKey privateKey, int keyType, Password password,
                                                  boolean strongEncryption) throws CryptoException, IOException {
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
     * @param applicationSettings Password quality configuration
     * @param res                 ResourceBundle
     * @throws CryptoException
     * @throws IOException
     */
    public static void exportAsOpenSsl(PrivateKey privateKey, String alias, JFrame frame,
                                       ApplicationSettings applicationSettings, ResourceBundle res)
            throws CryptoException, IOException {
        File exportFile = null;

        try {
            DExportPrivateKeyOpenSsl dExportPrivateKeyOpenSsl =
                    new DExportPrivateKeyOpenSsl(frame, alias, applicationSettings.getPasswordQualityConfig());
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
        } catch (FileNotFoundException ex) {
            String message = MessageFormat.format(res.getString("ExportKeyPairPrivateKeyAction.NoWriteFile.message"),
                                                  exportFile);
            JOptionPane.showMessageDialog(frame, message,
                                          res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyOpenSsl.Title"),
                                          JOptionPane.WARNING_MESSAGE);
        }
    }

    private static byte[] getOpenSslEncodedPrivateKey(PrivateKey privateKey, boolean pemEncoded,
                                                      OpenSslPbeType pbeAlgorithm, Password password)
            throws CryptoException, IOException {
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
}
