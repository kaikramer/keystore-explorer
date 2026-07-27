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
package org.kse.gui;

import static java.text.MessageFormat.format;

import java.util.ResourceBundle;

import org.kse.gui.preferences.PreferencesManager;
import org.kse.utilities.os.OperatingSystem;

import com.formdev.flatlaf.FlatSystemProperties;
import com.formdev.flatlaf.util.SystemFileChooser;

/**
 * Simple factory that returns SystemFileChooser objects for the requested security
 * file types. Basically just supplies a SystemFileChooser object with the file
 * filter box completed appropriately.
 */
public class FileChooserFactory {
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

    public static final String KEYSTORE_EXT_1 = "ks";
    public static final String KEYSTORE_EXT_2 = "keystore";
    public static final String JKS_EXT = "jks";
    public static final String JCEKS_EXT = "jceks";
    public static final String BKS_EXT = "bks";
    public static final String UBER_EXT = "uber";
    public static final String BCFKS_EXT = "bcfks";
    public static final String PKCS12_KEYSTORE_EXT_1 = "p12";
    public static final String PKCS12_KEYSTORE_EXT_2 = "pfx";
    public static final String KDB_EXT = "kdb";
    public static final String STH_EXT = "sth";
    public static final String X509_EXT_1 = "cer";
    public static final String X509_EXT_2 = "crt";
    public static final String PKCS7_EXT_1 = "p7b";
    public static final String PKCS7_EXT_2 = "p7c";
    public static final String PKI_PATH_EXT = "pkipath";
    public static final String SPC_EXT = "spc";
    public static final String CET_EXT = "cet";
    public static final String PKCS8_EXT = "pkcs8";
    public static final String P8_EXT = "p8";
    public static final String P8E_EXT = "p8e";
    public static final String PK8_EXT = "pk8";
    public static final String PVK_EXT = "pvk";
    public static final String OPENSSL_PVK_EXT = "privkey";
    public static final String PUBLIC_KEY_EXT = "pubkey";
    public static final String PKCS10_CSR_EXT_1 = "p10";
    public static final String PKCS10_CSR_EXT_2 = "csr";
    public static final String SPKAC_CSR_EXT = "spkac";
    public static final String CA_REPLY_EXT = "p7r";
    public static final String CRL_EXT = "crl";
    public static final String JAR_EXT = "jar";
    public static final String ZIP_EXT = "zip";
    public static final String JAD_EXT = "jad";
    public static final String LIB_DLL_EXT = "dll";
    public static final String LIB_SO_EXT = "so";
    public static final String LIB_DYLIB_EXT = "dylib";
    public static final String PEM_EXT = "pem";
    public static final String JWK_EXT = "json";
    public static final String CMS_EXT_1 = "p7s";
    public static final String CMS_EXT_2 = "p7m";
    public static final String SIG_EXT = "sig";
    public static final String CSV_EXT = "csv";

    private static final String KEYSTORE_FILE_DESC =
            format(res.getString("FileChooserFactory.KeyStoreFiles"), PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2,
                   KEYSTORE_EXT_1, KEYSTORE_EXT_2, JKS_EXT, JCEKS_EXT, BKS_EXT, UBER_EXT, BCFKS_EXT, KDB_EXT, PEM_EXT);

    private static final String X509_FILE_DESC =
            format(res.getString("FileChooserFactory.CertificateFiles"), X509_EXT_1, X509_EXT_2);

    private static final String PKCS7_FILE_DESC =
            format(res.getString("FileChooserFactory.Pkcs7Files"), PKCS7_EXT_1, PKCS7_EXT_2);

    private static final String PKI_PATH_FILE_DESC =
            format(res.getString("FileChooserFactory.PkiPathFiles"), PKI_PATH_EXT);

    private static final String SPC_FILE_DESC = format(res.getString("FileChooserFactory.SpcFiles"), SPC_EXT);

    private static final String CET_FILE_DESC = format(res.getString("FileChooserFactory.CetFiles"), CET_EXT);

    private static final String KEY_FILE_DESC = format(res.getString("FileChooserFactory.KeyFiles"),
            PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2, P8_EXT, P8E_EXT, PKCS8_EXT, PK8_EXT, PEM_EXT, PVK_EXT,
            OPENSSL_PVK_EXT, JWK_EXT);

    private static final String PKCS12_FILE_DESC =
            format(res.getString("FileChooserFactory.Pkcs12Files"), PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2);

    private static final String PKCS8_FILE_DESC =
            format(res.getString("FileChooserFactory.Pkcs8Files"), P8_EXT, P8E_EXT, PKCS8_EXT, PK8_EXT);

    private static final String PVK_FILE_DESC = format(res.getString("FileChooserFactory.PvkFiles"), PVK_EXT);

    private static final String OPENSSL_PVK_FILE_DESC =
            format(res.getString("FileChooserFactory.OpenSslPvkFiles"), OPENSSL_PVK_EXT);

    private static final String PUBLIC_KEY_FILE_DESC =
            format(res.getString("FileChooserFactory.PublicKeyFiles"), PUBLIC_KEY_EXT);

    private static final String PKCS10_CSR_FILE_DESC =
            format(res.getString("FileChooserFactory.Pkcs10CsrFiles"), PKCS10_CSR_EXT_1, PKCS10_CSR_EXT_2);

    private static final String SPKAC_CSR_FILE_DESC =
            format(res.getString("FileChooserFactory.SpkacCsrFiles"), SPKAC_CSR_EXT);

    private static final String CA_REPLY_FILE_DESC =
            format(res.getString("FileChooserFactory.CaReplyFiles"), CA_REPLY_EXT);

    private static final String CRL_FILE_DESC = format(res.getString("FileChooserFactory.CrlFiles"), CRL_EXT);

    private static final String JAR_FILE_DESC = format(res.getString("FileChooserFactory.JarFiles"), JAR_EXT);

    private static final String ZIP_FILE_DESC = format(res.getString("FileChooserFactory.ZipFiles"), ZIP_EXT);

    private static final String JAD_FILE_DESC = format(res.getString("FileChooserFactory.JadFiles"), JAD_EXT);

    private static final String LIB_DLL_FILE_DESC =
            format(res.getString("FileChooserFactory.LibDllFiles"), LIB_DLL_EXT);

    private static final String LIB_SO_FILE_DESC = format(res.getString("FileChooserFactory.LibSoFiles"), LIB_SO_EXT);

    private static final String LIB_DYLIB_FILE_DESC =
            format(res.getString("FileChooserFactory.LibDylibFiles"), LIB_DYLIB_EXT);

    private static final String PEM_FILE_DESC = format(res.getString("FileChooserFactory.PemFiles"), PEM_EXT);

    private static final String STH_FILE_DESC = format(res.getString("FileChooserFactory.SthFiles"), STH_EXT);

    private static final String CMS_FILE_DESC =
            format(res.getString("FileChooserFactory.CmsSigFiles"), CMS_EXT_1, CMS_EXT_2);

    private static final String SIG_FILE_DESC =
            format(res.getString("FileChooserFactory.SignatureFiles"), SIG_EXT);

    private static final String CSV_FILE_DESC = format(res.getString("FileChooserFactory.CsvFiles"), CSV_EXT);

    private FileChooserFactory() {
    }

    /**
     * Get a SystemFileChooser with no filtered files
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getNoFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        return chooser;
    }

    /**
     * Get a SystemFileChooser with all filtered files
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getAllFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setAcceptAllFileFilterUsed(true);
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for Pem files
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getPemFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for KeyStore files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getKeyStoreFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(
                new SystemFileChooser.FileNameExtensionFilter(KEYSTORE_FILE_DESC, PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2,
                                            KEYSTORE_EXT_1, KEYSTORE_EXT_2, JKS_EXT, JCEKS_EXT, BKS_EXT, UBER_EXT,
                                            BCFKS_EXT, KDB_EXT, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for CMS key database stash (.sth) files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getSthFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(STH_FILE_DESC, STH_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for X.509 Certificate files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getX509FileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(X509_FILE_DESC, X509_EXT_1, X509_EXT_2));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for PKCS #7 Certificate files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getPkcs7FileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(PKCS7_FILE_DESC, PKCS7_EXT_1, PKCS7_EXT_2));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for PKI Path Certificate files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getPkiPathFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(PKI_PATH_FILE_DESC, PKI_PATH_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for SPC Certificate files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getSpcFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(SPC_FILE_DESC, SPC_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for CET files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getCetFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(CET_FILE_DESC, CET_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for Certificate and PKCS #7 Certificate files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getCertFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(X509_FILE_DESC, X509_EXT_1, X509_EXT_2));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PKCS7_FILE_DESC, PKCS7_EXT_1, PKCS7_EXT_2));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PKI_PATH_FILE_DESC, PKI_PATH_EXT));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(SPC_FILE_DESC, SPC_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for key pair and private key files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getKeyFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(KEY_FILE_DESC, PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2,
                P8_EXT, P8E_EXT, PKCS8_EXT, PK8_EXT, PEM_EXT, PVK_EXT, OPENSSL_PVK_EXT, JWK_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for PKCS #12 files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getPkcs12FileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(
                new SystemFileChooser.FileNameExtensionFilter(PKCS12_FILE_DESC, PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for PKCS #8 files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getPkcs8FileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(PKCS8_FILE_DESC, P8_EXT, P8E_EXT, PKCS8_EXT, PK8_EXT));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for PVK files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getPvkFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(PVK_FILE_DESC, PVK_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for OpenSSL private key files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getOpenSslPvkFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(OPENSSL_PVK_FILE_DESC, OPENSSL_PVK_EXT));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for public key files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getPublicKeyFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(PUBLIC_KEY_FILE_DESC, PUBLIC_KEY_EXT));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for CSR files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getCsrFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(PKCS10_CSR_FILE_DESC, PKCS10_CSR_EXT_1, PKCS10_CSR_EXT_2));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(SPKAC_CSR_FILE_DESC, SPKAC_CSR_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for PKCS #10 CSR files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getPkcs10FileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(PKCS10_CSR_FILE_DESC, PKCS10_CSR_EXT_1, PKCS10_CSR_EXT_2));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for SPKAC CSR files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getSpkacFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(SPKAC_CSR_FILE_DESC, SPKAC_CSR_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for CA reply files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getCaReplyFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(CA_REPLY_FILE_DESC, CA_REPLY_EXT));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for CRL files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getCrlFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(CRL_FILE_DESC, CRL_EXT));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(PEM_FILE_DESC, PEM_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for JAR and ZIP files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getArchiveFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(JAR_FILE_DESC, JAR_EXT));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(ZIP_FILE_DESC, ZIP_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for ZIP files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getZipFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(ZIP_FILE_DESC, ZIP_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for JAD files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getJadFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(JAD_FILE_DESC, JAD_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for library files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getLibFileChooser() {
        SystemFileChooser chooser = getFileChooser();

        if (OperatingSystem.isWindows()) {
            chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(LIB_DLL_FILE_DESC, LIB_DLL_EXT));
        } else if (OperatingSystem.isMacOs()) {
            chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(LIB_DYLIB_FILE_DESC, LIB_DYLIB_EXT));
        } else if (OperatingSystem.isLinux() || OperatingSystem.isUnix()) {
            chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(LIB_SO_FILE_DESC, LIB_SO_EXT));
        }

        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for signature files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getSignatureFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(CMS_FILE_DESC, CMS_EXT_1, CMS_EXT_2));
        chooser.addChoosableFileFilter(new SystemFileChooser.FileNameExtensionFilter(SIG_FILE_DESC, SIG_EXT));
        return chooser;
    }

    /**
     * Get a SystemFileChooser filtered for CSV files.
     *
     * @return SystemFileChooser object
     */
    public static SystemFileChooser getCsvFileChooser() {
        SystemFileChooser chooser = getFileChooser();
        chooser.setFileFilter(new SystemFileChooser.FileNameExtensionFilter(CSV_FILE_DESC, CSV_EXT));
        return chooser;
    }

   private static SystemFileChooser getFileChooser() {
       if (PreferencesManager.getPreferences().isNativeFileChooserEnabled()) {
           System.setProperty(FlatSystemProperties.USE_SYSTEM_FILE_CHOOSER, "true");
       } else {
           System.setProperty(FlatSystemProperties.USE_SYSTEM_FILE_CHOOSER, "false");
       }

       SystemFileChooser fileChooser = new SystemFileChooser();

        // show/hide hidden files
        fileChooser.setFileHidingEnabled(!PreferencesManager.getPreferences().isShowHiddenFilesEnabled());

        return fileChooser;
    }

}