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
        if (record == null || record.certificates().isEmpty()) {
            return null;
        }
        List<X509Certificate> certs = record.certificates();
        return certs.toArray(new Certificate[0]);
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
        } catch (Exception e) {
            throw new java.security.KeyStoreException("Could not store private key entry '" + alias + "'", e);
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
