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
package org.kse.crypto.signing;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.List;
import java.util.ResourceBundle;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Store;
import org.kse.crypto.CryptoException;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

/**
 * Provides utility methods relating to Cryptographic Message Syntax (CMS).
 */
public class CmsUtil {
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/signing/resources");

    private static final String CMS_PEM_TYPE = "CMS";
    private static final String PKCS7_PEM_TYPE = "PKCS7";

    private CmsUtil() {
    }

    /**
     * Loads a signature. If it is a detached signature, attempts to find and load the content.
     * Verification and counter signing require the content.
     *
     * @param signatureFile The signature file.
     * @param chooser       The file chooser to use for choosing the content file.
     * @return
     * @throws CryptoException
     */
    public static CMSSignedData loadSignature(File signatureFile, Supplier<File> chooser)
            throws CryptoException {

        try {
            byte[] signature = Files.readAllBytes(signatureFile.toPath());

            if (PemUtil.isPemFormat(signature)) {
                PemInfo signaturePem = PemUtil.decode(signature);
                if (signaturePem != null) {
                    signature = signaturePem.getContent();
                }
            }

            CMSSignedData signedData = new CMSSignedData(signature);

            if (signedData.isDetachedSignature()) {
                CMSProcessableFile content = loadDetachedContent(signatureFile, chooser);
                if (content != null) {
                    signedData = new CMSSignedData(content, signature);
                }
            }

            return signedData;
        } catch (IOException | CMSException e) {
            throw new CryptoException(res.getString("NoReadCms.exception.message"), e);
        }
    }

    private static CMSProcessableFile loadDetachedContent(File signatureFile, Supplier<File> chooser) {

        // Look for the content file. if not present, prompt for it.
        File contentFile = null;

        // First try file name with signature extension stripped.
        int extensionIndex = signatureFile.getAbsolutePath().lastIndexOf('.');
        if (extensionIndex > 0) {
            // Turn file_name.txt.p7s into file_name.txt
            String contentFileName = signatureFile.getAbsolutePath().substring(0, extensionIndex);
            if (Files.exists(Paths.get(contentFileName))) {
                contentFile = new File(contentFileName);
            }
        }

        // No file - ask for one (if chooser is available)
        if (contentFile == null && chooser != null) {
            contentFile = chooser.get();
            if (contentFile == null) {
                return null;
            }
        }

        return new CMSProcessableFile(contentFile);
    }

    public static boolean isCmsPemType(PemInfo pemInfo) {
        return pemInfo != null && (PKCS7_PEM_TYPE.equals(pemInfo.getType()) || CMS_PEM_TYPE.equals(pemInfo.getType()));
    }

    /**
     * PEM encode a CMS signature.
     *
     * @param cms The CMS signature
     * @return The PEM'd encoding
     */
    public static String getPem(CMSSignedData cms) throws CryptoException {
        try {
            // Use PKCS7 PEM header since it can be verified using GnuTLS certtool and OpenSSL.
            // GnuTLS certtool will not verify signatures with the CMS PEM header.
            PemInfo pemInfo = new PemInfo(PKCS7_PEM_TYPE, null, cms.getEncoded());
            return PemUtil.encode(pemInfo);
        } catch (IOException e) {
            throw new CryptoException(res.getString("CmsGetPemFailed.exception.message"), e);
        }
    }

    public static List<KseSignerInformation> convertSignerInformations(Collection<SignerInformation> signerInfos,
            Store<X509CertificateHolder> trustedCerts, Store<X509CertificateHolder> signatureCerts) {
        return signerInfos.stream().map(s -> new KseSignerInformation(s, trustedCerts, signatureCerts))
                .collect(Collectors.toList());
    }
}
