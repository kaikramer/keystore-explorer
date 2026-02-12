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

package org.kse.gui.actions;

import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.util.Store;
import org.kse.AuthorityCertificates;
import org.kse.crypto.CryptoException;
import org.kse.crypto.SecurityProvider;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Abstract base class for actions that utilize authority certificates for establishing
 * trust to third-party certificate authorities (e.g., time stamping server certificates).
 */
public abstract class AuthorityCertificatesVerifyAction extends AuthorityCertificatesAction {

    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public AuthorityCertificatesVerifyAction(KseFrame kseFrame) {
        super(kseFrame);
    }

    /**
     * Get the complete set of trusted certificates for establishing trust during signature
     * verification.
     *
     * @return Set<X509Certificate>
     * @throws CryptoException If there was a problem getting the trusted certificates.
     */
    protected Set<X509Certificate> getTrustedCertificates() throws CryptoException {
        KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

        // When a key store is loaded, use the key store for the trusted certs, and
        // include the CA certs if the user has enabled the CA certs in the preferences.
        if (history != null) {
            KeyStoreState currentState = history.getCurrentState();
            KseKeyStore keyStore = currentState.getKeyStore();

            KseKeyStore caCertificates = getCaCertificates();
            KseKeyStore windowsTrustedRootCertificates = getWindowsTrustedRootCertificates();

            // Perform cert lookup against current KeyStore
            Set<X509Certificate> trustedCerts = new HashSet<>();
            trustedCerts.addAll(extractCertificates(keyStore));

            if (caCertificates != null) {
                // Perform cert lookup against CA Certificates KeyStore
                trustedCerts.addAll(extractCertificates(caCertificates));
            }

            if (windowsTrustedRootCertificates != null) {
                // Perform cert lookup against Windows Trusted Root Certificates KeyStore
                trustedCerts.addAll(extractCertificates(windowsTrustedRootCertificates));
            }

            return trustedCerts;
        }

        // When a key store is NOT loaded, use the CA certs regardless of the users preferences.
        return getTrustedCertsNoPrefsAsSet();
    }

    protected Collection<X509Certificate> extractCertificates(KseKeyStore keystore) throws CryptoException {
        // By default use the X509CertUtil for extracting certs. This implementation provides
        // compatibility with jarsigner and other tools that expect trust certs to be stored
        // in a key store certificate entry.
        return X509CertUtil.extractCertificates(keystore);
    }

    /**
     * Gets the CA trusted certificates ignoring the user prefs for using
     * these key stores. The users preferences are ignored since these key
     * stores are used for establishing trust to time stamping certificates
     * by VerifySignatureAction and VerifyJarAction.
     *
     * @return
     * @throws CryptoException
     * @throws CertificateEncodingException
     */
    protected Store<X509CertificateHolder> getTrustedCertsNoPrefs()
            throws CryptoException, CertificateEncodingException {

        @SuppressWarnings("unchecked")
        Store<X509CertificateHolder> trustedCerts = new JcaCertStore(getTrustedCertsNoPrefsAsSet());
        return trustedCerts;
    }

    /*
     * A private method for getting the CA trusted certs (no user preferences) as a Set.
     */
    private Set<X509Certificate> getTrustedCertsNoPrefsAsSet() throws CryptoException {
        KseKeyStore caCertificates = getCaCertificatesNoPrefCheck();
        KseKeyStore windowsTrustedRootCertificates = getWindowsTrustedRootCertificatesNoPrefCheck();

        // Perform cert lookup against current KeyStore
        Set<X509Certificate> allCerts = new HashSet<>();

        if (caCertificates != null) {
            // Perform cert lookup against CA Certificates KeyStore
            allCerts.addAll(X509CertUtil.extractCertificates(caCertificates));
        }

        if (windowsTrustedRootCertificates != null) {
            // Perform cert lookup against Windows Trusted Root Certificates KeyStore
            allCerts.addAll(X509CertUtil.extractCertificates(windowsTrustedRootCertificates));
        }

        return allCerts;
    }

    /**
     * Get CA Certificates KeyStore.
     *
     * @return KeyStore or null if unavailable
     */
    private KseKeyStore getCaCertificatesNoPrefCheck() {
        AuthorityCertificates authorityCertificates = AuthorityCertificates.getInstance();

        KseKeyStore caCertificates = authorityCertificates.getCaCertificates();

        if (caCertificates == null) {
            caCertificates = loadCaCertificatesKeyStore();

            if (caCertificates != null) {
                authorityCertificates.setCaCertificates(caCertificates);
            }
        }

        return caCertificates;
    }

    /**
     * Get Windows Trusted Root Certificates KeyStore.
     *
     * @return KeyStore or null if unavailable
     * @throws CryptoException If a problem occurred getting the KeyStore
     */
    private KseKeyStore getWindowsTrustedRootCertificatesNoPrefCheck() throws CryptoException {
        AuthorityCertificates authorityCertificates = AuthorityCertificates.getInstance();

        KseKeyStore windowsTrustedRootCertificates = null;

        if (Security.getProvider(SecurityProvider.MS_CAPI.jce()) != null) {
            windowsTrustedRootCertificates = authorityCertificates.getWindowsTrustedRootCertificates();
        }

        return windowsTrustedRootCertificates;
    }

}
