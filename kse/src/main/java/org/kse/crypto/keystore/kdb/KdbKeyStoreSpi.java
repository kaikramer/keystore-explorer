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
package org.kse.crypto.keystore.kdb;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

/**
 * A KeyStore service provider implementation backed by a CMS key database ({@code .kdb})
 * as used by enterprise web and application servers. "CMS" here is the Certificate
 * Management System component of GSKit, unrelated to the RFC 5652 Cryptographic Message Syntax.
 *
 * <p>The whole database is protected by a single password: the database header is signed
 * with it and every private key is PBES2-encrypted with it. Entry passwords are therefore
 * expected to equal the KeyStore password.
 */
public class KdbKeyStoreSpi extends KeyStoreSpi {

    private KdbKeyDatabase db = KdbKeyDatabase.create();

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {

        if (stream == null) {
            // Creating a new, empty key database
            db = KdbKeyDatabase.create();
            return;
        }

        byte[] data = stream.readAllBytes();

        if (!KdbKeyDatabase.isKeyDatabase(data)) {
            throw new IOException("Not a CMS key database (bad magic/type tag)");
        }

        if (password != null && !KdbKeyDatabase.verify(data, password)) {
            throw new IOException("Password verification failed",
                                  new UnrecoverableKeyException("CMS key database password incorrect"));
        }

        db = KdbKeyDatabase.read(data);
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException {
        stream.write(db.serialize(password));
        stream.flush();
    }

    @Override
    public Key engineGetKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException {
        KdbRecord record = db.find(alias);
        if (record == null || !record.hasPrivateKey()) {
            return null;
        }
        try {
            return record.privateKey(password);
        } catch (Exception e) {
            UnrecoverableKeyException uke =
                    new UnrecoverableKeyException("Could not decrypt private key of entry '" + alias + "'");
            uke.initCause(e);
            throw uke;
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        KdbRecord record = db.find(alias);
        if (record == null || record.certificate() == null) {
            return null;
        }
        // The leaf lives in this record; its signers are separate trusted records. Rebuild
        // the chain by following issuer links so callers (and PKCS#12 export) see leaf..root.
        List<X509Certificate> chain = assembleChain(record.certificate());
        return chain.toArray(new Certificate[0]);
    }

    /**
     * Builds an ordered certificate chain (leaf first) from {@code leaf} by following
     * issuer-to-subject links across every certificate stored in the database. Stops at a
     * self-signed certificate or when no issuer is present (a partial chain), and guards
     * against loops.
     */
    private List<X509Certificate> assembleChain(X509Certificate leaf) {
        List<X509Certificate> all = new ArrayList<>();
        for (KdbRecord record : db.records()) {
            all.addAll(record.certificates());
        }
        List<X509Certificate> chain = new ArrayList<>();
        X509Certificate current = leaf;
        while (current != null && !chain.contains(current)) {
            chain.add(current);
            if (current.getSubjectX500Principal().equals(current.getIssuerX500Principal())) {
                break; // self-signed root
            }
            current = findIssuer(current, all, chain);
        }
        return chain;
    }

    /**
     * Finds the issuer of {@code cert} among {@code candidates}, skipping certs already used.
     * Where several certificates share the issuer's DN — for example a cross-signed (dual-signed)
     * CA that has been certified by more than one root — the candidate whose public key actually
     * verifies {@code cert}'s signature is preferred, and a self-signed anchor is preferred over a
     * further intermediate so assembly heads towards a trust root. Falls back to a DN-only match so
     * a chain can still be built when the issuer's key is not held in the database.
     */
    private static X509Certificate findIssuer(X509Certificate cert, List<X509Certificate> candidates,
                                              List<X509Certificate> used) {
        X509Certificate dnMatch = null;
        X509Certificate verified = null;
        for (X509Certificate candidate : candidates) {
            if (used.contains(candidate)
                    || !candidate.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                continue;
            }
            if (dnMatch == null) {
                dnMatch = candidate;
            }
            if (!signed(cert, candidate)) {
                continue; // shares the issuer DN but did not actually sign cert
            }
            if (candidate.getSubjectX500Principal().equals(candidate.getIssuerX500Principal())) {
                return candidate; // a verified self-signed anchor is the best possible choice
            }
            if (verified == null) {
                verified = candidate;
            }
        }
        return verified != null ? verified : dnMatch;
    }

    /** True if {@code issuer}'s public key verifies {@code cert}'s signature. */
    private static boolean signed(X509Certificate cert, X509Certificate issuer) {
        try {
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        KdbRecord record = db.find(alias);
        return record != null ? record.certificate() : null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return null;
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(db.records().stream().map(KdbRecord::label).toList());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return db.find(alias) != null;
    }

    @Override
    public int engineSize() {
        return db.records().size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        KdbRecord record = db.find(alias);
        return record != null && record.hasPrivateKey();
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        KdbRecord record = db.find(alias);
        return record != null && !record.hasPrivateKey() && record.certificate() != null;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        for (KdbRecord record : db.records()) {
            if (record.certificate() != null && record.certificate().equals(cert)) {
                return record.label();
            }
        }
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
            throws java.security.KeyStoreException {
        if (alias == null) {
            throw new IllegalArgumentException("alias cannot be null");
        }
        if (!(key instanceof PrivateKey)) {
            throw new java.security.KeyStoreException("Only private keys are supported");
        }
        if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
            throw new java.security.KeyStoreException(
                    "A CMS key database entry requires an X.509 certificate for the private key");
        }
        try {
            byte[] encryptedKey = KdbRecord.encryptPrivateKey((PrivateKey) key, password);
            KdbRecord record = KdbRecord.personalRecord(alias, (X509Certificate) chain[0], encryptedKey);
            db.remove(alias);
            db.add(record);
            // A CMS key database stores the leaf in the personal record and every signer
            // in the chain as a separate trusted-certificate record, the same way gskcapicmd
            // does. Persist chain[1..n] so the signing chain is not lost on import.
            for (int i = 1; i < chain.length; i++) {
                if (!(chain[i] instanceof X509Certificate)) {
                    continue;
                }
                X509Certificate ca = (X509Certificate) chain[i];
                if (containsCertificate(ca)) {
                    continue;
                }
                db.add(KdbRecord.caRecord(uniqueLabel(signerLabel(ca)), ca));
            }
        } catch (Exception e) {
            throw new java.security.KeyStoreException("Could not store private key entry '" + alias + "'", e);
        }
    }

    /** True if a certificate equal to {@code cert} is already stored under any label. */
    private boolean containsCertificate(X509Certificate cert) {
        for (KdbRecord record : db.records()) {
            for (X509Certificate existing : record.certificates()) {
                if (existing.equals(cert)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Derives a signer label from a certificate's subject CN, falling back to the full DN. */
    private static String signerLabel(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        try {
            for (javax.naming.ldap.Rdn rdn : new javax.naming.ldap.LdapName(dn).getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    String cn = String.valueOf(rdn.getValue()).trim();
                    if (!cn.isEmpty()) {
                        return cn;
                    }
                }
            }
        } catch (javax.naming.InvalidNameException e) {
            // fall through to the raw DN
        }
        return dn.isEmpty() ? "signer" : dn;
    }

    /** Makes {@code base} unique among existing labels by appending " (n)" on collision. */
    private String uniqueLabel(String base) {
        if (db.find(base) == null) {
            return base;
        }
        for (int n = 2; ; n++) {
            String candidate = base + " (" + n + ")";
            if (db.find(candidate) == null) {
                return candidate;
            }
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
            throws java.security.KeyStoreException {
        throw new java.security.KeyStoreException(
                "Storing already protected keys is not supported by CMS key databases");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert)
            throws java.security.KeyStoreException {
        if (alias == null) {
            throw new IllegalArgumentException("alias cannot be null");
        }
        if (!(cert instanceof X509Certificate)) {
            throw new java.security.KeyStoreException("Only X.509 certificates are supported");
        }
        try {
            KdbRecord record = KdbRecord.caRecord(alias, (X509Certificate) cert);
            db.remove(alias);
            db.add(record);
        } catch (Exception e) {
            throw new java.security.KeyStoreException("Could not store certificate entry '" + alias + "'", e);
        }
    }

    @Override
    public void engineDeleteEntry(String alias) {
        if (alias == null) {
            throw new IllegalArgumentException("alias cannot be null");
        }
        db.remove(alias);
    }
}
