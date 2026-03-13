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

package org.kse.utilities;

import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.function.Function;

import org.kse.crypto.CryptoException;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.secretkey.PasswordType;
import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.crypto.x509.X509CertUtil;

/**
 * Utilities for creating unique alias names.
 */
public final class AliasUtil {

    // Utility pattern
    private AliasUtil() {
    }

    /**
     * Generates an unique alias in a key store for a certificate.
     *
     * @param keyStore The key store
     * @param cert     The certificate
     * @return An unique alias
     */
    public static String uniqueAlias(KseKeyStore keyStore, Certificate cert) {
        try {
            X509Certificate x509Cert = X509CertUtil.convertCertificate(cert);
            return uniqueAlias(keyStore, x509Cert);
        } catch (CryptoException e) {
            return uniqueAlias(keyStore, (String) null);
        }
    }

    /**
     * Generates an unique alias in a key store for a certificate.
     *
     * @param keyStore The key store
     * @param cert     The certificate
     * @return An unique alias
     */
    public static String uniqueAlias(KseKeyStore keyStore, X509Certificate cert) {
        return uniqueAlias(keyStore, X509CertUtil.getCertificateAlias(cert));
    }

    /**
     * Generates an unique alias in a key store for a secret key.
     *
     * @param keyStore      The key store
     * @param secretKeyType The secret key type
     * @return An unique alias
     */
    public static String uniqueAlias(KseKeyStore keyStore, SecretKeyType secretKeyType) {
        return uniqueAlias(keyStore, secretKeyType != null ? secretKeyType.friendly() : null);
    }

    /**
     * Generates an unique alias in a key store for a passphrase.
     *
     * @param keyStore     The key store
     * @param passwordType The secret key type
     * @return An unique alias
     */
    public static String uniqueAlias(KseKeyStore keyStore, PasswordType passwordType) {
        return uniqueAlias(keyStore, passwordType != null ? passwordType.friendly() : null);
    }

    /**
     * Makes an unique alias in a key store.
     *
     * @param keyStore The key store
     * @param alias    The alias to make unique
     * @return An unique alias
     */
    public static String uniqueAlias(KseKeyStore keyStore, String alias) {
        return uniqueAlias(t -> {
            try {
                return keyStore.containsAlias(t);
            } catch (KeyStoreException e) {
                return false;
            }
        }, alias);
    }

    /**
     * Generates an unique alias in a entry set for a certificate.
     *
     * @param aliases The set of aliases
     * @param cert    The certificate
     * @return An unique alias
     */
    public static String uniqueAlias(Set<String> aliases, X509Certificate cert) {
        return uniqueAlias(aliases::contains, X509CertUtil.getCertificateAlias(cert));
    }

    private static String uniqueAlias(Function<String, Boolean> matcher, String alias) {
        if (StringUtils.isBlank(alias)) {
            alias = "entry";
        }

        int index = 1;
        String proposedAlias = alias;
        while (matcher.apply(proposedAlias)) {
            proposedAlias = alias + " (" + index++ + ")";
        }

        return proposedAlias;
    }
}
