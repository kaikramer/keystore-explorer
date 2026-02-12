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
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStore.Entry;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * A KseKeyStore adapter that makes the KeyChainStore look and act
 * like an MS CAPI KeyStore. KSE expects that changes to key stores
 * backed by PKCS#11, MS CAPI, and Apple KeyChain to be automatically
 * persisted as this is how the PKCS#11 and MS CAPI key store providers
 * work. The KeychainStore requires calling store() to persist the
 * changes. This adapter adds a side-effect to the set methods so that
 * the changes are stored immediately.
 *
 * If the changes are not stored immediately, the private key is null,
 * and actions that require the private key will display unfriendly
 * error messages.
 */
public class KeychainStoreAdapter extends KseKeyStore {

    /**
     * Constructs a new KeychainStoreAdapter.
     *
     * @param keyStore The KeyStore to wrap.
     */
    public KeychainStoreAdapter(KeyStore keyStore) {
        super(keyStore);
    }

    @Override
    public void setKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        super.setKeyEntry(alias, key, password, chain);
        store();
    }

    @Override
    public void setKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        super.setKeyEntry(alias, key, chain);
        store();
    }

    @Override
    public void setCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        super.setCertificateEntry(alias, cert);
        store();
    }

    @Override
    public void deleteEntry(String alias) throws KeyStoreException {
        super.deleteEntry(alias);
        store();
    }

    @Override
    public void setEntry(String alias, Entry entry, ProtectionParameter protParam) throws KeyStoreException {
        super.setEntry(alias, entry, protParam);
        store();
    }

    private void store() throws KeyStoreException {
        try {
            store(null, null);
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KeyStoreException(e);
        }
    }

}
