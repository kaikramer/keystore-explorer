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

package org.kse.crypto.keystore;

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.encryptedData;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.certBag;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.data;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_friendlyName;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.x509Certificate;
import static org.kse.KSE.BC;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.kse.crypto.secretkey.SecretKeyUtil;
import org.kse.crypto.x509.X509CertUtil;

/**
 * A KeyStore adapter for PKCS #12 files that performs a low-level parse of the
 * PKCS #12 content to identify any certificates that are not visible when reading
 * the file using the Java PKCS12 key store provider.
 *
 * This adapter has methods for exposing the hidden certificates.
 */
public class Pkcs12KeyStoreAdapter extends KseKeyStore {

    private CertificateFactory certificateFactory;
    private List<CertEntry> invisibleCerts;

    /**
     * A record that represents a certificate entry (alias and certificate)
     *
     * @param alias The alias for the certificate
     * @param cert  The certificate
     */
    public static record CertEntry (
        String alias,
        Certificate cert
    ) {}

    /**
     * Constructs a new Pkcs12KeyStoreAdapter.
     *
     * @param keyStore The KeyStore to wrap.
     */
    public Pkcs12KeyStoreAdapter(KeyStore keyStore) {
        super(keyStore);
    }

    @Override
    public void load(InputStream stream, char[] password)
            throws NoSuchAlgorithmException, CertificateException, IOException {

        certificateFactory = CertificateFactory.getInstance(X509CertUtil.X509_CERT_TYPE);

        byte[] data = stream.readAllBytes();

        super.load(new ByteArrayInputStream(data), password);

        Set<Certificate> visibleCerts = extractAllCertificates();
        invisibleCerts = parseP12(data, password).stream() //
                .filter(ce -> !visibleCerts.contains(ce.cert)) //
                .toList();
    }

    private Set<Certificate> extractAllCertificates() {
        Set<Certificate> certs = new HashSet<>();
        try {
            for (Enumeration<String> aliases = aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();

                try {
                    if (isCertificateEntry(alias)) {
                        certs.add(getCertificate(alias));
                    } else if (isKeyEntry(alias)) {
                        Collections.addAll(certs, getCertificateChain(alias));
                    }
                } catch (KeyStoreException e) {
                    // ignore  -- just trying to find the visible certs
                }
            }
        } catch (KeyStoreException e) {
            // ignore -- the key store will always be initialized
        }
        return certs;
    }

    /**
     *
     * @return True if the PKCS #12 contains certificates that are not exposed by the Java PKCS12
     *         provider.
     */
    public boolean hasInvisibleCerts() {
        return !invisibleCerts.isEmpty();
    }

    /**
     *
     * @return The list of invisible certificates.
     */
    public List<CertEntry> getInvisibleCerts() {
        return Collections.unmodifiableList(invisibleCerts);
    }

    private List<CertEntry> parseP12(byte[] p12Data, char[] password) throws IOException {
        List<CertEntry> certificates = new ArrayList<>();

        Pfx pfx = Pfx.getInstance(ASN1Primitive.fromByteArray(p12Data));

        ContentInfo authSafe = pfx.getAuthSafe();

        if (authSafe.getContentType().equals(data)) {

            ASN1OctetString octetString = ASN1OctetString.getInstance(pfx.getAuthSafe().getContent());
            ContentInfo[] safeContents = AuthenticatedSafe.getInstance(octetString.getOctets()).getContentInfo();

            for (ContentInfo safeContent : safeContents) {

                if (safeContent.getContentType().equals(data)) {

                    try (ASN1InputStream dIn = new ASN1InputStream(((ASN1OctetString) safeContent.getContent()).getOctets())) {
                        readCertificates(certificates, (ASN1Sequence) dIn.readObject());
                    }
                } else if (safeContent.getContentType().equals(encryptedData)) {

                    // decrypt data
                    EncryptedData d = EncryptedData.getInstance(safeContent.getContent());
                    byte[] octets =
                            decryptData(d.getEncryptionAlgorithm(), password, d.getContent().getOctets());

                    if (octets.length == 0) {
                        continue;
                    }

                    // process safe bags
                    readCertificates(certificates, ASN1Sequence.getInstance(octets));
                }
            }
        }

        return certificates;
    }

    private void readCertificates(List<CertEntry> certificates, ASN1Sequence seq) {
        for (ASN1Encodable asn1Encodable : seq) {
            SafeBag b = SafeBag.getInstance(asn1Encodable);

            CertEntry certificate = readCertificate(b);
            if (certificate != null) {
                certificates.add(certificate);
            }
        }
    }

    private CertEntry readCertificate(SafeBag safeBag) {

        if (!safeBag.getBagId().equals(certBag)) {
            return null;
        }

        CertBag cb = CertBag.getInstance(safeBag.getBagValue());
        if (!cb.getCertId().equals(x509Certificate)) {
            return null;
        }

        try {
            ByteArrayInputStream cIn = new ByteArrayInputStream(((ASN1OctetString) cb.getCertValue()).getOctets());
            return new CertEntry(getFriendlyName(safeBag), certificateFactory.generateCertificate(cIn));
        } catch (Exception e) {
            return null;
        }
    }

    private String getFriendlyName(SafeBag b) {

        if (b.getBagAttributes() != null) {
            Enumeration<?> e = b.getBagAttributes().getObjects();

            while (e.hasMoreElements()) {
                ASN1Sequence sq = (ASN1Sequence) e.nextElement();
                ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier) sq.getObjectAt(0);
                ASN1Set attrSet = (ASN1Set) sq.getObjectAt(1);
                ASN1Primitive attr = null;

                if (attrSet.size() > 0) {
                    attr = (ASN1Primitive) attrSet.getObjectAt(0);
                }

                if (aOid.equals(pkcs_9_at_friendlyName) && attr != null) {
                    return ((DERBMPString) attr).getString();
                }
            }
        }

        return null;
    }

    private byte[] decryptData(AlgorithmIdentifier algId, char[] password, byte[] data) {

        ASN1ObjectIdentifier algorithm = algId.getAlgorithm();

        if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
            PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());
            PBEKeySpec pbeSpec = new PBEKeySpec(password);

            try {
                var keyFact = SecretKeyFactory.getInstance(algorithm.getId());
                var defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());
                SecretKey key = keyFact.generateSecret(pbeSpec);

                Cipher cipher = Cipher.getInstance(algorithm.getId());
                cipher.init(Cipher.DECRYPT_MODE, key, defParams);
                return cipher.doFinal(data);
            } catch (Exception e) {
                // Ignore since a failure in cert decryption shouldn't prevent opening the key store.
            }
        } else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2)) {
            try {
                Cipher cipher = createPBES2Cipher(password, algId);
                return cipher.doFinal(data);
            } catch (Exception e) {
                // Ignore since a failure in cert decryption shouldn't prevent opening the key store.
            }
        }

        return new byte[0];
    }

    private Cipher createPBES2Cipher(char[] password, AlgorithmIdentifier algId)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        PBES2Parameters pbes2Parameters = PBES2Parameters.getInstance(algId.getParameters());
        PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(pbes2Parameters.getKeyDerivationFunc().getParameters());
        AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(pbes2Parameters.getEncryptionScheme());

        ASN1ObjectIdentifier derivationFunctionOid = pbes2Parameters.getKeyDerivationFunc().getAlgorithm();
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(derivationFunctionOid.getId(), BC);

        byte[] salt = pbkdf2Params.getSalt();
        int iterations = pbkdf2Params.getIterationCount().intValue();
        int keySize = SecretKeyUtil.getKeySize(encScheme);

        SecretKey key;
        if (pbkdf2Params.isDefaultPrf()) {
            key = keyFact.generateSecret(new PBEKeySpec(password, salt, iterations, keySize));
        } else {
            key = keyFact.generateSecret(new PBKDF2KeySpec(password, salt, iterations, keySize, pbkdf2Params.getPrf()));
        }

        Cipher cipher = Cipher.getInstance(encScheme.getAlgorithm().getId(), BC);
        ASN1Encodable encParams = pbes2Parameters.getEncryptionScheme().getParameters();

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));

        return cipher;
    }
}
