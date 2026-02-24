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

package org.kse.crypto.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import javax.security.auth.x500.X500Principal;

import org.kse.crypto.CryptoException;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.privatekey.EncryptionType;
import org.kse.crypto.privatekey.OpenSslPbeType;
import org.kse.crypto.privatekey.OpenSslPvkUtil;
import org.kse.crypto.privatekey.Pkcs8PbeType;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.StringUtils;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

/**
 * A KeyStore service provider implementation that uses a PEM file for the backing store.
 *
 * This implementation is specific to KSE, and it would require replacing the KSE specifics
 * to make it a stand alone implementation.
 */
public class PemKeyStoreSpi extends KeyStoreSpi {

    private final Map<String, Entry> entries = new LinkedHashMap<>();

    private static class Entry {
        private PrivateKey key;
        private Certificate[] chain;
        private boolean isPkcs1;

        private Entry(PrivateKey key, boolean isPkcs1) {
            this.key = key;
            this.isPkcs1 = isPkcs1;
        }

        private Entry(PrivateKey key, Certificate[] chain) {
            this.key = key;
            this.chain = chain;
        }

        private Entry(Certificate chain) {
            this.chain = new Certificate[] {chain};
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {

        entries.clear();
        if (stream == null) {
            return;
        }

        List<PemInfo> blocks = PemUtil.decodeAll(stream.readAllBytes());

        List<Entry> keys = new ArrayList<>();
        List<Certificate> certs = new ArrayList<>();

        try {
            Password pass = null;
            if (password != null && password.length > 0) {
                pass = new Password(password);
            }

            for (PemInfo pem : blocks) {
                switch (pem.getType()) {
                    case Pkcs8Util.PKCS8_UNENC_PVK_PEM_TYPE:
                        keys.add(new Entry(Pkcs8Util.load(pem.getContent()), false));
                        break;

                    case Pkcs8Util.PKCS8_ENC_PVK_PEM_TYPE:
                        keys.add(new Entry(Pkcs8Util.loadEncrypted(pem.getContent(), pass), false));
                        break;

                    case OpenSslPvkUtil.OPENSSL_RSA_PVK_PEM_TYPE:
                    case OpenSslPvkUtil.OPENSSL_EC_PVK_PEM_TYPE:
                    case OpenSslPvkUtil.OPENSSL_DSA_PVK_PEM_TYPE:
                        PrivateKey key;
                        if (OpenSslPvkUtil.getEncryptionType(pem) == EncryptionType.ENCRYPTED) {
                            key = OpenSslPvkUtil.loadEncrypted(pem, pass);
                        } else {
                            key = OpenSslPvkUtil.load(pem.getContent());
                        }
                        keys.add(new Entry(key, true));
                        break;

                    case X509CertUtil.CERT_PEM_TYPE:
                        CertificateFactory cf = CertificateFactory.getInstance(X509CertUtil.X509_CERT_TYPE);
                        certs.add(cf.generateCertificate(new ByteArrayInputStream(pem.getContent())));
                        break;
                }
            }

            associateKeys(keys, certs);
        } catch (CryptoException e) {
            throw new NoSuchAlgorithmException(e);
        }
    }

    private void associateKeys(List<Entry> keyEntries, List<Certificate> certs) throws CryptoException {

        List<X509Certificate> x509Certs = new ArrayList<>();
        Map<X500Principal, List<X509Certificate>> bySubject = new HashMap<>();
        Map<X500Principal, List<X509Certificate>> byIssuer = new HashMap<>();

        for (Certificate cert : certs) {
            X509Certificate x509Cert = X509CertUtil.convertCertificate(cert);
            x509Certs.add(x509Cert);

            bySubject.computeIfAbsent(
                    x509Cert.getSubjectX500Principal(), k -> new ArrayList<>()).add(x509Cert);

            byIssuer.computeIfAbsent(
                    x509Cert.getIssuerX500Principal(), k -> new ArrayList<>()).add(x509Cert);
        }

        // Build full certificate chain for each key
        int aliasIndex = 1;
        for (Entry keyEntry : keyEntries) {

            X509Certificate leaf = findCertificateForKey(keyEntry.key, x509Certs);

            if (leaf != null) {
                keyEntry.chain = buildCertificateChain(leaf, bySubject, byIssuer);

                String alias = X509CertUtil.getCertificateAlias(leaf);
                if (StringUtils.isBlank(alias)) {
                    alias = "key";
                }
                String indexedAlias = alias;
                while (entries.containsKey(indexedAlias)) {
                    indexedAlias = alias + aliasIndex++;
                }
                entries.put(indexedAlias, keyEntry);
            }
        }

        // Add standalone certificates
        aliasIndex = 1;
        for (X509Certificate cert : x509Certs) {
            boolean used = entries.values().stream()
                    .anyMatch(e -> Stream.of(e.chain).anyMatch(c -> c.equals(cert)));
            if (!used) {
                String alias = X509CertUtil.getCertificateAlias(cert);
                if (StringUtils.isBlank(alias)) {
                    alias = "cert";
                }
                String indexedAlias = alias;
                while (entries.containsKey(indexedAlias)) {
                    indexedAlias = alias + aliasIndex++;
                }
                entries.put(indexedAlias, new Entry(cert));
            }
        }
    }

    private X509Certificate findCertificateForKey(PrivateKey key, List<X509Certificate> x509Certs) {
        for (X509Certificate cert : x509Certs) {
            try {
                PublicKey pub = cert.getPublicKey();
                if (KeyPairUtil.validKeyPair(key, pub)) {
                    return cert;
                }
            } catch (CryptoException e) {
                // ignore failures
            }
        }
        return null;
    }

    private X509Certificate[] buildCertificateChain(X509Certificate leaf,
            Map<X500Principal, List<X509Certificate>> bySubject, Map<X500Principal, List<X509Certificate>> byIssuer) {

        List<X509Certificate> chain = new ArrayList<>();
        chain.add(leaf);

        X509Certificate current = leaf;
        Set<X509Certificate> visited = new HashSet<>();
        visited.add(current);

        while (true) {
            X500Principal issuer = current.getIssuerX500Principal();
            X500Principal subject = current.getSubjectX500Principal();

            // Stop at self-signed root
            if (issuer.equals(subject)) {
                break;
            }

            List<X509Certificate> issuers = bySubject.get(issuer);
            if (issuers == null || issuers.isEmpty()) {
                break;
            }

            // PEM bundles rarely contain ambiguous chains; pick the first
            X509Certificate next = issuers.get(0);

            if (visited.contains(next)) {
                break;
            }

            chain.add(next);
            visited.add(next);
            current = next;
        }

        return chain.toArray(X509Certificate[]::new);
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, CertificateException {
        Set<Certificate> written = new HashSet<>();
        try {
            Password pass = null;
            if (password != null && password.length > 0) {
                pass = new Password(password);
            }

            for (Map.Entry<String, Entry> me : entries.entrySet()) {
                Entry entry = me.getValue();

                if (entry.key != null) {
                    String keyPem;
                    if (entry.isPkcs1) {
                        if (pass != null) {
                            keyPem = OpenSslPvkUtil.getEncrypted(entry.key, OpenSslPbeType.AES_256BIT_CBC, pass);
                        } else {
                            keyPem = OpenSslPvkUtil.getPem(entry.key);
                        }
                    } else {
                        if (pass != null) {
                            keyPem = Pkcs8Util.getEncryptedPem(entry.key, Pkcs8PbeType.PBES2_AES256_SHA256, pass);
                        } else {
                            keyPem = Pkcs8Util.getPem(entry.key);
                        }
                    }
                    stream.write(keyPem.getBytes(StandardCharsets.US_ASCII));
                }

                X509Certificate[] certs = X509CertUtil.convertCertificates(entry.chain);
                for (X509Certificate cert : certs) {
                    if (!written.contains(cert)) {
                        stream.write(X509CertUtil.getCertEncodedX509Pem(cert).getBytes(StandardCharsets.US_ASCII));
                        written.add(cert);
                    }
                }
            }
        } catch (CryptoException e) {
            throw new CertificateException(e);
        }
        stream.flush();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) {
        Entry e = entries.get(alias);
        return e != null ? e.key : null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        Entry e = entries.get(alias);
        return e != null ? e.chain : null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        Entry e = entries.get(alias);
        return (e != null && e.chain != null) ? e.chain[0] : null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return null;
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(entries.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return entries.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return entries.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        Entry e = entries.get(alias);
        return e != null && e.key != null;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        Entry e = entries.get(alias);
        return e != null && e.key == null && e.chain != null;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        for (Map.Entry<String, Entry> me : entries.entrySet()) {
            Entry entry = me.getValue();
            if (entry.chain != null && entry.chain.length > 0 && entry.chain[0].equals(cert)) {
                return me.getKey();
            }
        }
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        if (alias == null) {
            throw new IllegalArgumentException("alias cannot be null");
        }
        if (!(key instanceof PrivateKey)) {
            throw new IllegalArgumentException("key must be a PrivateKey");
        }
        entries.put(alias, new Entry((PrivateKey) key, chain));
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) {
        if (alias == null) {
            throw new IllegalArgumentException("alias cannot be null");
        }
        entries.put(alias, new Entry(cert));
    }

    @Override
    public void engineDeleteEntry(String alias) {
        if (alias == null) {
            throw new IllegalArgumentException("alias cannot be null");
        }
        entries.remove(alias);
    }
}
