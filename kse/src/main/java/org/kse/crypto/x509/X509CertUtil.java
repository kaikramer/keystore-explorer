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
package org.kse.crypto.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.ResourceBundle;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.X509TrustedCertificateBlock;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.preferences.PreferencesManager;
import org.kse.utilities.SerialNumbers;
import org.kse.utilities.StringUtils;
import org.kse.utilities.io.HexUtil;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

/**
 * Provides utility methods relating to X509 Certificates and CRLs.
 */
public final class X509CertUtil {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
    private static final String X509_CERT_TYPE = "X.509";
    private static final String PKCS7_ENCODING = "PKCS7";
    private static final String PKI_PATH_ENCODING = "PkiPath";
    private static final String CERT_PEM_TYPE = "CERTIFICATE";
    private static final String PKCS7_PEM_TYPE = "PKCS7";

    public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
    public static final String BASE64_TESTER = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9" +
                                               "+/]{2}==)$";

    private X509CertUtil() {
    }

    /**
     * Load one or more certificates from the specified stream.
     *
     * @param certsBytes BA to load certificates from
     * @return The certificates
     * @throws CryptoException Problem encountered while loading the certificate(s)
     */
    public static X509Certificate[] loadCertificates(byte[] certsBytes) throws CryptoException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, KSE.BC);

            // try to parse data as PEM encoded
            List<X509Certificate> loadedCerts = loadAsPEM(certsBytes, cf);

            // might be Base64 encoded but without the PEM header
            if (loadedCerts.isEmpty()) {
                loadedCerts = loadAsBase64(certsBytes, cf);
            }

            // try to parse as DER encoded
            if (loadedCerts.isEmpty()) {
                Collection<? extends Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(certsBytes));
                loadedCerts = convertCertificates(certs);
            }

            return loadedCerts.toArray(new X509Certificate[0]);
        } catch (CertificateException ex) {
            // Failed to load certificates, may be pki path encoded - try loading as that
            try {
                return loadCertificatesPkiPath(new ByteArrayInputStream(certsBytes));
            } catch (CryptoException ex2) {
                throw new CryptoException(res.getString("NoLoadCertificate.exception.message"), ex);
            }
        }
    }

    private static List<X509Certificate> loadAsBase64(byte[] certsBytes, CertificateFactory cf) {
        try {
            byte[] base64Decoded = Base64.getMimeDecoder().decode(certsBytes);

            Collection<? extends Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(base64Decoded));

            return convertCertificates(certs);
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    private static X509Certificate[] loadCertificatesPkiPath(InputStream is) throws CryptoException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, KSE.BC);
            CertPath certPath = cf.generateCertPath(is, PKI_PATH_ENCODING);

            List<? extends Certificate> certs = certPath.getCertificates();

            ArrayList<X509Certificate> loadedCerts = new ArrayList<>();

            for (Certificate certificate : certs) {
                X509Certificate cert = (X509Certificate) certificate;

                if (cert != null) {
                    loadedCerts.add(cert);
                }
            }

            return loadedCerts.toArray(new X509Certificate[0]);
        } catch (CertificateException e) {
            throw new CryptoException(res.getString("NoLoadPkiPath.exception.message"), e);
        } finally {
            IOUtils.closeQuietly(is);
        }
    }

    private static List<X509Certificate> loadAsPEM(byte[] bytes, CertificateFactory cf) {

        PEMParser pemParser = new PEMParser(new StringReader(new String(bytes)));
        JcaX509CertificateConverter jcaX509CertConverter = new JcaX509CertificateConverter();

        List<X509Certificate> certs = new ArrayList<>();

        try {
            Object pemObject = pemParser.readObject();
            while (pemObject != null) {
                // check for all possible certificate classes
                if (pemObject instanceof X509CertificateHolder) {
                    certs.add(jcaX509CertConverter.getCertificate((X509CertificateHolder) pemObject));
                } else if (pemObject instanceof X509TrustedCertificateBlock) {
                    X509TrustedCertificateBlock trustedCertBlock = (X509TrustedCertificateBlock) pemObject;
                    certs.add(jcaX509CertConverter.getCertificate(trustedCertBlock.getCertificateHolder()));
                } else if (pemObject instanceof ContentInfo) {
                    ContentInfo contentInfo = (ContentInfo) pemObject;
                    Collection<? extends Certificate> certsFromPkcs7 = cf.generateCertificates(
                            new ByteArrayInputStream(contentInfo.getEncoded()));

                    if (!certsFromPkcs7.isEmpty()) {
                        List<X509Certificate> x509Certificates = convertCertificates(certsFromPkcs7);
                        certs.addAll(x509Certificates);
                    }
                }
                pemObject = pemParser.readObject();
            }
            return certs;
        } catch (IOException | CertificateException | CryptoException e) {
            return certs;
        }
    }

    /**
     * Load a CRL from the specified stream.
     *
     * @param crlData BA to load CRL from
     * @return The CRL
     * @throws CryptoException Problem encountered while loading the CRL
     */
    public static X509CRL loadCRL(byte[] crlData) throws CryptoException {

        if (crlData == null || crlData.length == 0) {
            throw new CryptoException(res.getString("NoLoadCrl.exception.message"),
                                      new IllegalArgumentException("CRL data is empty"));
        }

        try {
            CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, KSE.BC);
            return (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlData));
        } catch (CertificateException | CRLException ex) {
            throw new CryptoException(res.getString("NoLoadCrl.exception.message"), ex);
        }
    }

    /**
     * Convert the supplied array of certificate objects into X509Certificate
     * objects.
     *
     * @param certsIn The Certificate objects
     * @return The converted X509Certificate objects
     * @throws CryptoException A problem occurred during the conversion
     */
    public static X509Certificate[] convertCertificates(Certificate[] certsIn) throws CryptoException {

        if (certsIn == null) {
            return new X509Certificate[0];
        }

        X509Certificate[] certsOut = new X509Certificate[certsIn.length];

        for (int i = 0; i < certsIn.length; i++) {
            certsOut[i] = convertCertificate(certsIn[i]);
        }

        return certsOut;
    }

    /**
     * Convert the supplied array of certificate objects into X509Certificate
     * objects.
     *
     * @param certs The Certificate objects
     * @return The converted X509Certificate objects
     * @throws CryptoException A problem occurred during the conversion
     */
    public static List<X509Certificate> convertCertificates(Collection<? extends Certificate> certs)
            throws CryptoException {

        ArrayList<X509Certificate> convertedCerts = new ArrayList<>();

        if (certs == null) {
            return convertedCerts;
        }

        for (Certificate cert : certs) {
            convertedCerts.add(convertCertificate(cert));
        }

        return convertedCerts;
    }

    /**
     * Convert the supplied certificate object into an X509Certificate object.
     *
     * @param certIn The Certificate object
     * @return The converted X509Certificate object
     * @throws CryptoException A problem occurred during the conversion
     */
    public static X509Certificate convertCertificate(Certificate certIn) throws CryptoException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, KSE.BC);
            ByteArrayInputStream bais = new ByteArrayInputStream(certIn.getEncoded());
            return (X509Certificate) cf.generateCertificate(bais);
        } catch (CertificateException e) {
            throw new CryptoException(res.getString("NoConvertCertificate.exception.message"), e);
        }
    }

    /**
     * Order the supplied array of X.509 certificates in issued to issuer order.
     *
     * @param certs X.509 certificates
     * @return The ordered X.509 certificates
     */
    public static X509Certificate[] orderX509CertChain(X509Certificate[] certs) {

        if (certs == null) {
            return new X509Certificate[0];
        }

        if (certs.length <= 1) {
            return certs;
        }

        // Put together each possible certificate path...
        ArrayList<ArrayList<X509Certificate>> paths = new ArrayList<>();

        // For each possible path...
        for (X509Certificate cert : certs) {
            // Each possible path assumes a different certificate is the root issuer
            ArrayList<X509Certificate> path = new ArrayList<>();
            X509Certificate issuerCert = cert;
            path.add(issuerCert);

            X509Certificate newIssuer = null;

            // Recursively build that path by finding the next issued certificate
            while ((newIssuer = findIssuedCert(issuerCert, certs)) != null) {
                // Found an issued cert, now attempt to find its issued certificate
                issuerCert = newIssuer;
                path.add(0, newIssuer);
            }

            // Path complete
            paths.add(path);
        }

        // Get longest path - this will be the ordered path
        ArrayList<X509Certificate> longestPath = paths.get(0);
        for (int i = 1; i < paths.size(); i++) {
            ArrayList<X509Certificate> path = paths.get(i);
            if (path.size() > longestPath.size()) {
                longestPath = path;
            }
        }

        // Return longest path
        return longestPath.toArray(new X509Certificate[0]);
    }
    /*
     * Tries to sort the certificates according to their hierarchy, 
     * and adds at the end those that have no dependencies.
     */
    public static X509Certificate[] orderX509CertsChain(X509Certificate[] certs) {
        if (certs == null) {
            return new X509Certificate[0];
        }
        if (certs.length <= 1) {
            return certs;
        }
        ArrayList<ArrayList<X509Certificate>> paths = new ArrayList<>();
        for (X509Certificate cert : certs) {
            ArrayList<X509Certificate> path = new ArrayList<>();
            path.add(cert);
            for (X509Certificate issuerCert : certs) {
                if (certificatesEquals(issuerCert, cert)) {
                    continue;
                }
                if (isIssuedBy(cert, issuerCert)) {
                    path.add(issuerCert);
                }
            }
            if (path.size() > 1) {
                paths.add(path);
            }
        }
        List<X509Certificate> listCertificates = new ArrayList<>();
        for (ArrayList<X509Certificate> path : paths) {
            X509Certificate cert = path.get(0);
            X509Certificate issuerCert = path.get(1);
            int posIssuer = -1;
            int posCert = -1;
            for (int i = 0; i < listCertificates.size(); i++) {
                X509Certificate cert2 = listCertificates.get(i);
                if (certificatesEquals(issuerCert, cert2)) {
                    posIssuer = i;
                }
                if (certificatesEquals(cert, cert2)) {
                    posCert = i;
                }
            }
            if (posIssuer == -1) {
                if (posCert == -1) {
                    listCertificates.add(cert);
                }
                listCertificates.add(issuerCert);
            } else {
                listCertificates.add(posIssuer, cert);
            }
        }
        if (listCertificates.size() != certs.length) {
            for (X509Certificate cert1 : certs) {
                boolean found = false;
                for (X509Certificate cert2 : listCertificates) {
                    if (certificatesEquals(cert1, cert2)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    listCertificates.add(cert1);
                }
            }
        }
        return listCertificates.toArray(new X509Certificate[0]);
    }

    private static boolean certificatesEquals(X509Certificate cert1, X509Certificate cert2) {
        return cert1.getSubjectX500Principal().equals(cert2.getSubjectX500Principal())
                && cert1.getIssuerX500Principal().equals(cert2.getIssuerX500Principal())
                && cert1.getSerialNumber().equals(cert2.getSerialNumber());
    }

    private static X509Certificate findIssuedCert(X509Certificate issuerCert, X509Certificate[] certs) {
        // Find a certificate issued by the supplied certificate
        for (X509Certificate cert : certs) {
            if (issuerCert.getSubjectX500Principal().equals(cert.getSubjectX500Principal()) &&
                issuerCert.getIssuerX500Principal().equals(cert.getIssuerX500Principal()) &&
                issuerCert.getSerialNumber().equals(cert.getSerialNumber())) {
                // Checked certificate is issuer - ignore it
                continue;
            }

            if (isIssuedBy(cert, issuerCert)) {
                return cert;
            }
        }
        return null;
    }

    /**
     * Checks if certificate was issued by the other certificate by checking first the DN and only if the issuer DN
     * matches the subject DN, then the signature is verified. This avoids the slow verification operation when it is
     * impossible that the second certificate has signed the first one.
     *
     * @param cert The issued certificate
     * @param issuerCert The possible issuer certificate
     * @return True, if issuerCert has issued cert, false otherwise
     */
    public static boolean isIssuedBy(X509Certificate cert, X509Certificate issuerCert) {
        if (issuerCert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            // possible candidate found, now check if signature matches the issuer key
            try {
                if (verifyCertificate(cert, issuerCert)) {
                    return true;
                }
            } catch (CryptoException e) {
                // ignore technical verification issues as they are not relevant for finding chains
                return true;
            }
        }
        return false;
    }

    /**
     * X.509 encode a certificate.
     *
     * @param cert The certificate
     * @return The encoding
     * @throws CryptoException If there was a problem encoding the certificate
     */
    public static byte[] getCertEncodedX509(X509Certificate cert) throws CryptoException {
        try {
            return cert.getEncoded();
        } catch (CertificateException ex) {
            throw new CryptoException(res.getString("NoDerEncodeCertificate.exception.message"), ex);
        }
    }

    /**
     * X.509 encode a certificate and PEM the encoding.
     *
     * @param cert The certificate
     * @return The PEM'd encoding
     * @throws CryptoException If there was a problem encoding the certificate
     */
    public static String getCertEncodedX509Pem(X509Certificate cert) throws CryptoException {
        PemInfo pemInfo = new PemInfo(CERT_PEM_TYPE, null, getCertEncodedX509(cert));
        return PemUtil.encode(pemInfo);
    }

    /**
     * X.509 encode a number of certificates and PEM the encoding.
     *
     * @param certs The certificates
     * @return The PEM'd encoding
     * @throws CryptoException If there was a problem encoding the certificates
     */
    public static String getCertsEncodedX509Pem(X509Certificate[] certs) throws CryptoException {
        StringBuilder sb = new StringBuilder();
        for (X509Certificate cert : certs) {
            sb.append(getCertEncodedX509Pem(cert));
        }
        return sb.toString();
    }

    /**
     * PKCS #7 encode a certificate.
     *
     * @param cert The certificate
     * @return The encoding
     * @throws CryptoException If there was a problem encoding the certificate
     */
    public static byte[] getCertEncodedPkcs7(X509Certificate cert) throws CryptoException {
        return getCertsEncodedPkcs7(new X509Certificate[] { cert });
    }

    /**
     * PKCS #7 encode a number of certificates.
     *
     * @param certs The certificates
     * @return The encoding
     * @throws CryptoException If there was a problem encoding the certificates
     */
    public static byte[] getCertsEncodedPkcs7(X509Certificate[] certs) throws CryptoException {
        try {
            ArrayList<Certificate> encodedCerts = new ArrayList<>();

            Collections.addAll(encodedCerts, certs);

            CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, KSE.BC);

            CertPath cp = cf.generateCertPath(encodedCerts);

            return cp.getEncoded(PKCS7_ENCODING);
        } catch (CertificateException e) {
            throw new CryptoException(res.getString("NoPkcs7Encode.exception.message"), e);
        }
    }

    /**
     * PKCS #7 encode a certificate and PEM the encoding.
     *
     * @param cert The certificate
     * @return The PEM'd encoding
     * @throws CryptoException If there was a problem encoding the certificate
     */
    public static String getCertEncodedPkcs7Pem(X509Certificate cert) throws CryptoException {
        return getCertsEncodedPkcs7Pem(new X509Certificate[] { cert });
    }

    /**
     * PKCS #7 encode a number of certificates and PEM the encoding.
     *
     * @param certs The certificates
     * @return The PEM'd encoding
     * @throws CryptoException If there was a problem encoding the certificates
     */
    public static String getCertsEncodedPkcs7Pem(X509Certificate[] certs) throws CryptoException {
        PemInfo pemInfo = new PemInfo(PKCS7_PEM_TYPE, null, getCertsEncodedPkcs7(certs));
        return PemUtil.encode(pemInfo);
    }

    /**
     * PKI Path encode a certificate.
     *
     * @param cert The certificate
     * @return The encoding
     * @throws CryptoException If there was a problem encoding the certificate
     */
    public static byte[] getCertEncodedPkiPath(X509Certificate cert) throws CryptoException {
        return getCertsEncodedPkiPath(new X509Certificate[] { cert });
    }

    /**
     * PKI Path encode a number of certificates.
     *
     * @param certs The certificates
     * @return The encoding
     * @throws CryptoException If there was a problem encoding the certificates
     */
    public static byte[] getCertsEncodedPkiPath(X509Certificate[] certs) throws CryptoException {
        try {
            ArrayList<Certificate> encodedCerts = new ArrayList<>();

            Collections.addAll(encodedCerts, certs);

            CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE, KSE.BC);

            CertPath cp = cf.generateCertPath(encodedCerts);

            return cp.getEncoded(PKI_PATH_ENCODING);
        } catch (CertificateException e) {
            throw new CryptoException(res.getString("NoPkcs7Encode.exception.message"), e);
        }
    }

    /**
     * Verify that one X.509 certificate was signed using the private key that
     * corresponds to the public key of a second certificate.
     *
     * @param signedCert  The signed certificate
     * @param signingCert The signing certificate
     * @return True if the first certificate was signed by private key
     *         corresponding to the second signature
     * @throws CryptoException If there was a problem verifying the signature.
     */
    public static boolean verifyCertificate(X509Certificate signedCert, X509Certificate signingCert)
            throws CryptoException {
        try {
            signedCert.verify(signingCert.getPublicKey());
            return true;
        } catch (InvalidKeyException | SignatureException ex) {
            // Verification failed
            return false;
        } catch (NoSuchProviderException | NoSuchAlgorithmException | CertificateException ex) {
            // Problem verifying
            throw new CryptoException(res.getString("NoVerifyCertificate.exception.message"), ex);
        }
    }

    /**
     * Check whether or not a trust path exists between the supplied X.509
     * certificate and the supplied keystores based on the trusted
     * certificates contained therein, ie that a chain of trust exists between
     * the supplied certificate and a self-signed trusted certificate in the
     * KeyStores.
     *
     * @param cert      The certificate
     * @param keyStores The KeyStores
     * @return The trust chain, or null if trust could not be established
     * @throws CryptoException If there is a problem establishing trust
     */
    public static X509Certificate[] establishTrust(X509Certificate cert, KeyStore[] keyStores) throws CryptoException {
        ArrayList<X509Certificate> ksCerts = new ArrayList<>();

        for (KeyStore keyStore : keyStores) {
            ksCerts.addAll(extractCertificates(keyStore));
        }

        return establishTrust(cert, ksCerts);
    }

    private static X509Certificate[] establishTrust(X509Certificate cert, List<X509Certificate> compCerts)
            throws CryptoException {
        /*
         * Check whether or not a trust path exists between the supplied X.509
         * certificate and the supplied comparison certificates , ie that a
         * chain of trust exists between the certificate and a self-signed
         * trusted certificate in the comparison set
         */

        for (int i = 0; i < compCerts.size(); i++) {
            X509Certificate compCert = compCerts.get(i);

            // Verify of certificate issuer is sam as comparison certificate's subject
            if (cert.getIssuerX500Principal().equals(compCert.getSubjectX500Principal())) {
                // Verify if the comparison certificate's private key was used to sign the certificate
                if (X509CertUtil.verifyCertificate(cert, compCert)) {
                    // If the comparision certificate is self-signed then a chain of trust exists
                    if (compCert.getSubjectX500Principal().equals(compCert.getIssuerX500Principal())) {
                        return new X509Certificate[] { cert, compCert };
                    }

                    /*
                     * Otherwise try and establish a chain of trust from the
                     * comparison certificate against the other comparison certificates
                     */
                    X509Certificate[] tmpChain = establishTrust(compCert, compCerts);
                    if (tmpChain != null) {
                        X509Certificate[] trustChain = new X509Certificate[tmpChain.length + 1];

                        trustChain[0] = cert;

                        System.arraycopy(tmpChain, 0, trustChain, 1, tmpChain.length);

                        return trustChain;
                    }
                }
            }
        }

        return null; // No chain of trust
    }

    private static List<X509Certificate> extractCertificates(KeyStore keyStore) throws CryptoException {
        try {
            List<X509Certificate> certs = new ArrayList<>();

            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();

                if (keyStore.isCertificateEntry(alias)) {
                    certs.add(X509CertUtil.convertCertificate(keyStore.getCertificate(alias)));
                }
            }

            return certs;
        } catch (KeyStoreException ex) {
            throw new CryptoException(res.getString("NoExtractCertificates.exception.message"), ex);
        }
    }

    /**
     * Check whether or not a trusted certificate in the supplied KeyStore
     * matches the supplied X.509 certificate.
     *
     * @param cert     The certificate
     * @param keyStore The KeyStore
     * @return The alias of the matching certificate in the KeyStore or null if
     *         there is no match
     * @throws CryptoException If there is a problem establishing trust
     */
    public static String matchCertificate(KeyStore keyStore, X509Certificate cert) throws CryptoException {
        try {
            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();
                if (keyStore.isCertificateEntry(alias)) {
                    X509Certificate compCert = X509CertUtil.convertCertificate(keyStore.getCertificate(alias));

                    if (cert.equals(compCert)) {
                        return alias;
                    }
                }
            }
            return null;
        } catch (KeyStoreException ex) {
            throw new CryptoException(res.getString("NoMatchCertificate.exception.message"), ex);
        }
    }

    /**
     * For a given X.509 certificate get a representative alias for it in a
     * KeyStore. For a self-signed certificate this will be the subject's common
     * name (if any). For a non-self-signed certificate it will be the subject's
     * common name followed by the issuer's common name in brackets. Aliases
     * will always be in lower case.
     *
     * @param cert The certificate
     * @return The alias or a blank string if none could be worked out
     */
    public static String getCertificateAlias(X509Certificate cert) {
        X500Principal subject = cert.getSubjectX500Principal();
        X500Principal issuer = cert.getIssuerX500Principal();

        String subjectCn = X500NameUtils.extractCN(X500NameUtils.x500PrincipalToX500Name(subject));
        String issuerCn = X500NameUtils.extractCN(X500NameUtils.x500PrincipalToX500Name(issuer));

        if (StringUtils.isBlank(subjectCn)) {
            return "";
        }

        if (StringUtils.isBlank(issuerCn) || subjectCn.equals(issuerCn)) {
            return subjectCn;
        }

        return MessageFormat.format("{0} ({1})", subjectCn, issuerCn);
    }

    /**
     * Get short name for certificate. Common name if available, otherwise use
     * entire distinguished name.
     *
     * @param cert Certificate
     * @return Short name
     */
    public static String getShortName(X509Certificate cert) {
        X500Name subject = X500NameUtils.x500PrincipalToX500Name(cert.getSubjectX500Principal());

        String shortName = X500NameUtils.extractCN(subject);

        if (StringUtils.isBlank(shortName)) {
            shortName = subject.toString();
        }

        // subject DN can be empty in some cases
        if (StringUtils.isBlank(shortName)) {
            shortName = cert.getSerialNumber().toString();
        }

        return shortName;
    }

    /**
     * For a given X.509 certificate get the algorithm of its signature. Useful
     * as the JCE may return an unfriendly name. This method converts known
     * "unfriendly names" to friendly names.
     *
     * @param cert The certificate
     * @return The algorithm
     */
    public static String getCertificateSignatureAlgorithm(X509Certificate cert) {
        // Unfriendly JCE sig names may be actual JCE names or OIDs
        String algorithm = cert.getSigAlgName();

        SignatureType type = SignatureType.resolveJce(algorithm);

        if (type != null) {
            algorithm = type.friendly();
        } else {
            String sigAlgOID = cert.getSigAlgOID();
            byte[] sigAlgParams = cert.getSigAlgParams();
            type = SignatureType.resolveOid(sigAlgOID, sigAlgParams);

            if (type != null) {
                algorithm = type.friendly();
            }
        }

        return algorithm;
    }

    /**
     * Is the supplied X.509 certificate self-signed?
     *
     * @param cert The certificate
     * @return True if it is
     */
    public static boolean isCertificateSelfSigned(X509Certificate cert) {
        return cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
    }

    /**
     * Return certificate serial number as hexadecimal string
     *
     * @param cert a certificate
     * @return Serial number as hex string
     */
    public static String getSerialNumberAsHex(X509Certificate cert) {
        return HexUtil.getHexString(cert.getSerialNumber(), "0x", 0, 0);
    }

    /**
     * Return certificate serial number as decimal string
     *
     * @param cert a certificate
     * @return Serial number as decimal string
     */
    public static String getSerialNumberAsDec(X509Certificate cert) {
        return new BigInteger(1, cert.getSerialNumber().toByteArray()).toString(10);
    }

    /**
     * Generate certificate serial number with the length configured in the application preferences.
     *
     * @return Serial number as hex string with "0x" prefix
     */
    public static String generateCertSerialNumber() {
        int snLength = PreferencesManager.getPreferences().getSerialNumberLengthInBytes();
        return HexUtil.getHexString(SerialNumbers.generate(snLength), "0x", 0, 0);
    }
}
