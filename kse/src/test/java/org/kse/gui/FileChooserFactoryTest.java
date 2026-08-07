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

import static org.assertj.core.api.Assertions.assertThat;
import static org.kse.gui.FileChooserFactory.BCFKS_EXT;
import static org.kse.gui.FileChooserFactory.BKS_EXT;
import static org.kse.gui.FileChooserFactory.CA_REPLY_EXT;
import static org.kse.gui.FileChooserFactory.CET_EXT;
import static org.kse.gui.FileChooserFactory.CMS_EXT_1;
import static org.kse.gui.FileChooserFactory.CMS_EXT_2;
import static org.kse.gui.FileChooserFactory.CRL_EXT;
import static org.kse.gui.FileChooserFactory.CSV_EXT;
import static org.kse.gui.FileChooserFactory.JAD_EXT;
import static org.kse.gui.FileChooserFactory.JAR_EXT;
import static org.kse.gui.FileChooserFactory.JCEKS_EXT;
import static org.kse.gui.FileChooserFactory.JKS_EXT;
import static org.kse.gui.FileChooserFactory.JWK_EXT;
import static org.kse.gui.FileChooserFactory.KDB_EXT;
import static org.kse.gui.FileChooserFactory.KEYSTORE_EXT_1;
import static org.kse.gui.FileChooserFactory.KEYSTORE_EXT_2;
import static org.kse.gui.FileChooserFactory.LIB_DLL_EXT;
import static org.kse.gui.FileChooserFactory.LIB_DYLIB_EXT;
import static org.kse.gui.FileChooserFactory.LIB_SO_EXT;
import static org.kse.gui.FileChooserFactory.OPENSSL_PVK_EXT;
import static org.kse.gui.FileChooserFactory.PEM_EXT;
import static org.kse.gui.FileChooserFactory.PKCS10_CSR_EXT_1;
import static org.kse.gui.FileChooserFactory.PKCS10_CSR_EXT_2;
import static org.kse.gui.FileChooserFactory.PKCS12_KEYSTORE_EXT_1;
import static org.kse.gui.FileChooserFactory.PKCS12_KEYSTORE_EXT_2;
import static org.kse.gui.FileChooserFactory.PKCS7_EXT_1;
import static org.kse.gui.FileChooserFactory.PKCS7_EXT_2;
import static org.kse.gui.FileChooserFactory.PKCS8_EXT;
import static org.kse.gui.FileChooserFactory.PKI_PATH_EXT;
import static org.kse.gui.FileChooserFactory.PK8_EXT;
import static org.kse.gui.FileChooserFactory.PUBLIC_KEY_EXT;
import static org.kse.gui.FileChooserFactory.PVK_EXT;
import static org.kse.gui.FileChooserFactory.P8E_EXT;
import static org.kse.gui.FileChooserFactory.P8_EXT;
import static org.kse.gui.FileChooserFactory.SIG_EXT;
import static org.kse.gui.FileChooserFactory.SPC_EXT;
import static org.kse.gui.FileChooserFactory.SPKAC_CSR_EXT;
import static org.kse.gui.FileChooserFactory.STH_EXT;
import static org.kse.gui.FileChooserFactory.UBER_EXT;
import static org.kse.gui.FileChooserFactory.X509_EXT_1;
import static org.kse.gui.FileChooserFactory.X509_EXT_2;
import static org.kse.gui.FileChooserFactory.ZIP_EXT;

import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.kse.utilities.os.OperatingSystem;

import com.formdev.flatlaf.util.SystemFileChooser;
import com.formdev.flatlaf.util.SystemFileChooser.FileFilter;
import com.formdev.flatlaf.util.SystemFileChooser.FileNameExtensionFilter;

/**
 * Tests for {@link FileChooserFactory}.
 * <p>
 * These tests exist because the behavior depends on an implementation detail of the underlying FlatLaf
 * {@link SystemFileChooser}: calling {@code setFileFilter()} and afterward calling
 * {@code addChoosableFileFilter()} one or more times can silently replace ("swallow") the previously set
 * default filter - and even remove it from the list of choosable filters entirely. The tests verify both
 * the full, ordered list of choosable file filters and the filter that ends up selected as default for
 * every chooser created by {@link FileChooserFactory}.
 * </p>
 */
class FileChooserFactoryTest {

    // sentinel used in the expected/actual filter key lists to represent the "All Files" filter
    private static final String ACCEPT_ALL = "*";
    private static final List<String> ACCEPT_ALL_FILTER = List.of(ACCEPT_ALL);

    @Test
    void noFileChooserHasOnlyAcceptAllFilter() {
        assertFilters(FileChooserFactory::getNoFileChooser, List.of(ACCEPT_ALL_FILTER), ACCEPT_ALL_FILTER);
    }

    @Test
    void allFileChooserHasOnlyAcceptAllFilter() {
        assertFilters(FileChooserFactory::getAllFileChooser, List.of(ACCEPT_ALL_FILTER), ACCEPT_ALL_FILTER);
    }

    @Test
    void pemFileChooser() {
        List<String> pem = ext(PEM_EXT);
        assertFilters(FileChooserFactory::getPemFileChooser, List.of(ACCEPT_ALL_FILTER, pem), pem);
    }

    @Test
    void keyStoreFileChooser() {
        List<String> keystore = ext(PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2, KEYSTORE_EXT_1, KEYSTORE_EXT_2,
                JKS_EXT, JCEKS_EXT, BKS_EXT, UBER_EXT, BCFKS_EXT, KDB_EXT, PEM_EXT);
        assertFilters(FileChooserFactory::getKeyStoreFileChooser, List.of(ACCEPT_ALL_FILTER, keystore), keystore);
    }

    @Test
    void sthFileChooser() {
        List<String> sth = ext(STH_EXT);
        assertFilters(FileChooserFactory::getSthFileChooser, List.of(ACCEPT_ALL_FILTER, sth), sth);
    }

    @Test
    void x509FileChooser() {
        List<String> x509 = ext(X509_EXT_1, X509_EXT_2);
        List<String> pem = ext(PEM_EXT);
        assertFilters(FileChooserFactory::getX509FileChooser, List.of(ACCEPT_ALL_FILTER, x509, pem), x509);
    }

    @Test
    void pkcs7FileChooser() {
        List<String> pkcs7 = ext(PKCS7_EXT_1, PKCS7_EXT_2);
        List<String> pem = ext(PEM_EXT);
        assertFilters(FileChooserFactory::getPkcs7FileChooser, List.of(ACCEPT_ALL_FILTER, pkcs7, pem), pkcs7);
    }

    @Test
    void pkiPathFileChooser() {
        List<String> pkiPath = ext(PKI_PATH_EXT);
        assertFilters(FileChooserFactory::getPkiPathFileChooser, List.of(ACCEPT_ALL_FILTER, pkiPath), pkiPath);
    }

    @Test
    void spcFileChooser() {
        List<String> spc = ext(SPC_EXT);
        assertFilters(FileChooserFactory::getSpcFileChooser, List.of(ACCEPT_ALL_FILTER, spc), spc);
    }

    @Test
    void cetFileChooser() {
        List<String> cet = ext(CET_EXT);
        assertFilters(FileChooserFactory::getCetFileChooser, List.of(ACCEPT_ALL_FILTER, cet), cet);
    }

    @Test
    void certFileChooser() {
        List<String> x509 = ext(X509_EXT_1, X509_EXT_2);
        List<String> pem = ext(PEM_EXT);
        List<String> pkcs7 = ext(PKCS7_EXT_1, PKCS7_EXT_2);
        List<String> pkiPath = ext(PKI_PATH_EXT);
        List<String> spc = ext(SPC_EXT);
        assertFilters(FileChooserFactory::getCertFileChooser,
                List.of(ACCEPT_ALL_FILTER, x509, pem, pkcs7, pkiPath, spc), x509);
    }

    @Test
    void keyFileChooser() {
        List<String> key = ext(PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2, P8_EXT, P8E_EXT, PKCS8_EXT, PK8_EXT,
                PEM_EXT, PVK_EXT, OPENSSL_PVK_EXT, JWK_EXT);
        assertFilters(FileChooserFactory::getKeyFileChooser, List.of(ACCEPT_ALL_FILTER, key), key);
    }

    @Test
    void pkcs12FileChooser() {
        List<String> pkcs12 = ext(PKCS12_KEYSTORE_EXT_1, PKCS12_KEYSTORE_EXT_2);
        assertFilters(FileChooserFactory::getPkcs12FileChooser, List.of(ACCEPT_ALL_FILTER, pkcs12), pkcs12);
    }

    @Test
    void pkcs8FileChooser() {
        List<String> pkcs8 = ext(P8_EXT, P8E_EXT, PKCS8_EXT, PK8_EXT);
        List<String> pem = ext(PEM_EXT);
        assertFilters(FileChooserFactory::getPkcs8FileChooser, List.of(ACCEPT_ALL_FILTER, pkcs8, pem), pkcs8);
    }

    @Test
    void pvkFileChooser() {
        List<String> pvk = ext(PVK_EXT);
        assertFilters(FileChooserFactory::getPvkFileChooser, List.of(ACCEPT_ALL_FILTER, pvk), pvk);
    }

    @Test
    void openSslPvkFileChooser() {
        List<String> openSslPvk = ext(OPENSSL_PVK_EXT);
        List<String> pem = ext(PEM_EXT);
        assertFilters(FileChooserFactory::getOpenSslPvkFileChooser, List.of(ACCEPT_ALL_FILTER, openSslPvk, pem),
                openSslPvk);
    }

    @Test
    void publicKeyFileChooser() {
        List<String> publicKey = ext(PUBLIC_KEY_EXT);
        List<String> pem = ext(PEM_EXT);
        assertFilters(FileChooserFactory::getPublicKeyFileChooser, List.of(ACCEPT_ALL_FILTER, publicKey, pem),
                publicKey);
    }

    @Test
    void csrFileChooser() {
        List<String> pkcs10Csr = ext(PKCS10_CSR_EXT_1, PKCS10_CSR_EXT_2);
        List<String> pem = ext(PEM_EXT);
        List<String> spkacCsr = ext(SPKAC_CSR_EXT);
        assertFilters(FileChooserFactory::getCsrFileChooser, List.of(ACCEPT_ALL_FILTER, pkcs10Csr, pem, spkacCsr),
                pkcs10Csr);
    }

    @Test
    void pkcs10FileChooser() {
        List<String> pkcs10Csr = ext(PKCS10_CSR_EXT_1, PKCS10_CSR_EXT_2);
        List<String> pem = ext(PEM_EXT);
        assertFilters(FileChooserFactory::getPkcs10FileChooser, List.of(ACCEPT_ALL_FILTER, pkcs10Csr, pem),
                pkcs10Csr);
    }

    @Test
    void spkacFileChooser() {
        List<String> spkacCsr = ext(SPKAC_CSR_EXT);
        assertFilters(FileChooserFactory::getSpkacFileChooser, List.of(ACCEPT_ALL_FILTER, spkacCsr), spkacCsr);
    }

    @Test
    void caReplyFileChooser() {
        List<String> caReply = ext(CA_REPLY_EXT);
        List<String> pem = ext(PEM_EXT);
        assertFilters(FileChooserFactory::getCaReplyFileChooser, List.of(ACCEPT_ALL_FILTER, caReply, pem), caReply);
    }

    @Test
    void crlFileChooser() {
        List<String> crl = ext(CRL_EXT);
        List<String> pem = ext(PEM_EXT);
        assertFilters(FileChooserFactory::getCrlFileChooser, List.of(ACCEPT_ALL_FILTER, crl, pem), crl);
    }

    @Test
    void archiveFileChooser() {
        List<String> jar = ext(JAR_EXT);
        List<String> zip = ext(ZIP_EXT);
        assertFilters(FileChooserFactory::getArchiveFileChooser, List.of(ACCEPT_ALL_FILTER, jar, zip), jar);
    }

    @Test
    void jadFileChooser() {
        List<String> jad = ext(JAD_EXT);
        assertFilters(FileChooserFactory::getJadFileChooser, List.of(ACCEPT_ALL_FILTER, jad), jad);
    }

    @Test
    void libFileChooser() {
        List<String> lib;
        if (OperatingSystem.isWindows()) {
            lib = ext(LIB_DLL_EXT);
        } else if (OperatingSystem.isMacOs()) {
            lib = ext(LIB_DYLIB_EXT);
        } else if (OperatingSystem.isLinux() || OperatingSystem.isUnix()) {
            lib = ext(LIB_SO_EXT);
        } else {
            lib = null;
        }
        List<List<String>> expected = lib != null ? List.of(ACCEPT_ALL_FILTER, lib) : List.of(ACCEPT_ALL_FILTER);
        assertFilters(FileChooserFactory::getLibFileChooser, expected, lib != null ? lib : ACCEPT_ALL_FILTER);
    }

    @Test
    void signatureFileChooser() {
        List<String> cms = ext(CMS_EXT_1, CMS_EXT_2);
        List<String> sig = ext(SIG_EXT);
        assertFilters(FileChooserFactory::getSignatureFileChooser, List.of(ACCEPT_ALL_FILTER, cms, sig), cms);
    }

    @Test
    void csvFileChooser() {
        List<String> csv = ext(CSV_EXT);
        assertFilters(FileChooserFactory::getCsvFileChooser, List.of(ACCEPT_ALL_FILTER, csv), csv);
    }

    /**
     * Builds the chooser, then asserts that the ordered list of choosable file filters and the selected
     * default file filter match the expected keys (see {@link #ext(String...)} and {@link #ACCEPT_ALL_FILTER}).
     */
    private void assertFilters(Supplier<SystemFileChooser> chooserSupplier, List<List<String>> expectedFilters,
            List<String> expectedSelectedFilter) {
        SystemFileChooser chooser = chooserSupplier.get();

        assertThat(filterKeys(chooser)).as("choosable file filters").isEqualTo(expectedFilters);
        assertThat(key(chooser, chooser.getFileFilter())).as("selected default file filter")
                .isEqualTo(expectedSelectedFilter);
    }

    // Builds the "key" used to identify an extension filter, independent of its (locale specific) description text.
    private static List<String> ext(String... extensions) {
        return Arrays.asList(extensions);
    }

    private static List<List<String>> filterKeys(SystemFileChooser chooser) {
        return Arrays.stream(chooser.getChoosableFileFilters())
                     .map(filter -> key(chooser, filter))
                     .collect(Collectors.toList());
    }

    private static List<String> key(SystemFileChooser chooser, FileFilter filter) {
        if (filter == chooser.getAcceptAllFileFilter()) {
            return ACCEPT_ALL_FILTER;
        }
        return Arrays.asList(((FileNameExtensionFilter) filter).getExtensions());
    }
}
