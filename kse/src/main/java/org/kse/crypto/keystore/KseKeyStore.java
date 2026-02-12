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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

/**
 * A KeyStore adapter for abstracting the differences in KeyStore provider
 * implementations.
 *
 * This decorator is 1:1 with java.security.KeyStore. Subclasses may add
 * side-effects that are not covered by the KeyStore documentation.
 */
@SuppressWarnings("javadoc")
public class KseKeyStore {

    private KeyStore keyStore;

    /**
     * Constructor for wrapping a KeyStore.
     *
     * @param keyStore The KeyStore to wrap.
     */
    public KseKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    /**
     * Returns underlying KeyStore object. KSE classes and methods
     * need to use the wrapper class. This method is exists to
     * provide compatibility with JDK methods that require a KeyStore.
     *
     * @return the keyStore
     */
    @Deprecated
    public KeyStore getKeyStore() {
        return keyStore;
    }

    public Provider getProvider() {
        return keyStore.getProvider();
    }

    public String getType() {
        return keyStore.getType();
    }

    // TODO Re-enable when Java 18+ is the default for KSE.
//    public Set<Entry.Attribute> getAttributes(String alias) throws KeyStoreException {
//        return keyStore.getAttributes(alias);
//    }

    public Key getKey(String alias, char[] password)
            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        return keyStore.getKey(alias, password);
    }

    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return keyStore.getCertificateChain(alias);
    }

    public Certificate getCertificate(String alias) throws KeyStoreException {
        return keyStore.getCertificate(alias);
    }

    public Date getCreationDate(String alias) throws KeyStoreException {
        return keyStore.getCreationDate(alias);
    }

    public void setKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        keyStore.setKeyEntry(alias, key, password, chain);
    }

    public void setKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        keyStore.setKeyEntry(alias, key, chain);
    }

    public void setCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        keyStore.setCertificateEntry(alias, cert);
    }

    public void deleteEntry(String alias) throws KeyStoreException {
        keyStore.deleteEntry(alias);
    }

    public Enumeration<String> aliases() throws KeyStoreException {
        return keyStore.aliases();
    }

    public boolean containsAlias(String alias) throws KeyStoreException {
        return keyStore.containsAlias(alias);
    }

    public int size() throws KeyStoreException {
        return keyStore.size();
    }

    public boolean isKeyEntry(String alias) throws KeyStoreException {
        return keyStore.isKeyEntry(alias);
    }

    public boolean isCertificateEntry(String alias) throws KeyStoreException {
        return keyStore.isCertificateEntry(alias);
    }

    public String getCertificateAlias(Certificate cert) throws KeyStoreException {
        return keyStore.getCertificateAlias(cert);
    }

    public void store(OutputStream out, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        keyStore.store(out, password);
    }

    public void store(LoadStoreParameter param)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        keyStore.store(param);
    }

    public void load(InputStream stream, char[] password)
            throws NoSuchAlgorithmException, CertificateException, IOException {
        keyStore.load(stream, password);
    }

    public void load(LoadStoreParameter param) throws NoSuchAlgorithmException, CertificateException, IOException {
        keyStore.load(param);
    }

    public Entry getEntry(String alias, ProtectionParameter protParam)
            throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        return keyStore.getEntry(alias, protParam);
    }

    public void setEntry(String alias, Entry entry, ProtectionParameter protParam) throws KeyStoreException {
        keyStore.setEntry(alias, entry, protParam);
    }

    public boolean entryInstanceOf(String alias, Class<? extends KeyStore.Entry> entryClass) throws KeyStoreException {
        return keyStore.entryInstanceOf(alias, entryClass);
    }
}
