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

import static org.kse.crypto.filetype.CryptoFileType.BCFKS_KS;
import static org.kse.crypto.filetype.CryptoFileType.BKS_KS;
import static org.kse.crypto.filetype.CryptoFileType.JCEKS_KS;
import static org.kse.crypto.filetype.CryptoFileType.JKS_KS;
import static org.kse.crypto.filetype.CryptoFileType.PEM_KS;
import static org.kse.crypto.filetype.CryptoFileType.PKCS12_KS;
import static org.kse.crypto.filetype.CryptoFileType.UBER_KS;

import java.util.Comparator;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.function.Function;

import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.filetype.CryptoFileType;
import org.kse.crypto.secretkey.PasswordType;
import org.kse.crypto.secretkey.SecretKeyType;

/**
 * Enumeration of KeyStore Types supported by the KeyStoreUtil class.
 */
public enum KeyStoreType {

    JKS("JKS", "KeyStoreType.Jks", true, false, JKS_KS),
    JCEKS("JCEKS", "KeyStoreType.Jceks", true, false, JCEKS_KS, SecretKeyType.SECRET_KEY_ALL, PasswordType.PASSWORD_ALL),
    PKCS12("PKCS12", "KeyStoreType.Pkcs12", true, false, PKCS12_KS, SecretKeyType.SECRET_KEY_PKCS12, PasswordType.PASSWORD_PKCS12),
    BKS("BKS", "KeyStoreType.Bks", true, true, BKS_KS, SecretKeyType.SECRET_KEY_ALL, PasswordType.PASSWORD_ALL),
    UBER("UBER", "KeyStoreType.Uber", true, true, UBER_KS, SecretKeyType.SECRET_KEY_ALL, PasswordType.PASSWORD_ALL),
    KEYCHAIN("KeychainStore", "KeyStoreType.AppleKeyChain", false, false, null),
    MS_CAPI_PERSONAL("Windows-MY", "KeyStoreType.MscapiPersonalCerts", false, true, null),
    MS_CAPI_ROOT("Windows-ROOT", "KeyStoreType.MscapiRootCerts", false, true, null),
    PKCS11("PKCS11", "KeyStoreType.Pkcs11", false, true, null),
    BCFKS("BCFKS", "KeyStoreType.Bcfks", true, true, BCFKS_KS, SecretKeyType.SECRET_KEY_BCFKS, PasswordType.PASSWORD_BCFKS),
    PEM("PEM", "KeyStoreType.Pem", true, true, PEM_KS),
    UNKNOWN("UNKNOWN", "KeyStoreType.Unknown", false, false, null);

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/keystore/resources");
    private String jce;
    private String friendlyKey;
    private boolean fileBased;
    private CryptoFileType cryptoFileType;
    private Set<SecretKeyType> supportedKeyTypes;
    private Set<PasswordType> supportedPasswordTypes;

    private Comparator<String> aliasComparator;
    private Function<String, String> normalizer;

    KeyStoreType(String jce, String friendlyKey, boolean fileBased, boolean caseSensitive, CryptoFileType cryptoFileType) {
        this(jce, friendlyKey, fileBased, caseSensitive, cryptoFileType, SecretKeyType.SECRET_KEY_NONE, PasswordType.PASSWORD_NONE);
    }

    KeyStoreType(String jce, String friendlyKey, boolean fileBased, boolean caseSensitive, CryptoFileType cryptoFileType,
            Set<SecretKeyType> supportedKeyTypes, Set<PasswordType> supportedPasswordTypes) {
        this.jce = jce;
        this.friendlyKey = friendlyKey;
        this.fileBased = fileBased;
        this.cryptoFileType = cryptoFileType;
        this.supportedKeyTypes = supportedKeyTypes;
        this.supportedPasswordTypes = supportedPasswordTypes;

        if (caseSensitive) {
            aliasComparator = KeyStoreType::compareCaseSensitive;
            normalizer = KeyStoreType::noop;
        } else {
            aliasComparator = KeyStoreType::compareCaseInsensitive;
            normalizer = KeyStoreType::toLowerCase;
        }
    }

    /**
     * Is the given KeyStoreType backed by the BC provider?
     *
     * @param keyStoreType KeyStoreType to check
     * @return True, if KeyStoreType is backed by the BC provider
     */
    public static boolean isBouncyCastleKeyStore(KeyStoreType keyStoreType) {
        return (keyStoreType == BKS || keyStoreType == UBER ||
                keyStoreType == BCFKS);
    }

    /**
     * Get KeyStore type JCE name.
     *
     * @return JCE name
     */
    public String jce() {
        return jce;
    }

    /**
     * KeyStore type friendly name.
     *
     * @return Friendly name
     */
    public String friendly() {
        return res.getString(friendlyKey);
    }

    /**
     * Is KeyStore type file based?
     *
     * @return True if it is, false otherwise
     */
    public boolean isFileBased() {
        return fileBased;
    }

    /**
     * Are key store entries password protected?
     *
     * @return True if it has, false otherwise
     */
    public boolean hasEntryPasswords() {
        return this != PKCS11 && this != MS_CAPI_PERSONAL && this != MS_CAPI_ROOT;
    }

    /**
     * Are key store entries using the same password as the key store?
     *
     * For PKCS #12 key stores, the entry password is always going to be the same as the key store
     * password.
     * For KeyChainStore key stores, a password is needed by the provider, but the password
     * is not used.
     * For PEM key stores, there isn't a key store password, but all entries will use the same
     * password so it's treated like a key store with a password.
     *
     * @return True if so, false otherwise
     */
    public boolean entrySameAsKeyStorePassword() {
        return this == PKCS12 || this == KEYCHAIN || this == PEM;
    }

    /**
     * Are private keys exportable for this keystore type?
     *
     * @return True if private keys are exportable, false otherwise
     */
    public boolean hasExportablePrivateKeys() {
        return this != PKCS11 && this != MS_CAPI_PERSONAL && this != MS_CAPI_ROOT;
    }

    /**
     * Does this KeyStore type support secret key entries?
     *
     * @return True, if secret key entries are supported by this KeyStore type
     */
    public boolean supportsKeyEntries() {
        return !supportedKeyTypes.isEmpty();
    }

    /**
     * Does this KeyStore type support the secret key type?
     *
     * @param secretKeyType The secret key type to check for support.
     * @return True, if secret key type is supported by this KeyStore type
     */
    public boolean supportsKeyType(SecretKeyType secretKeyType) {
        return supportedKeyTypes.contains(secretKeyType);
    }

    /**
     * Does this KeyStore type support the password type?
     *
     * @param passwordType The password type to check for support.
     * @return True, if password type is supported by this KeyStore type
     */
    public boolean supportsPasswordType(PasswordType passwordType) {
        return supportedPasswordTypes.contains(passwordType);
    }

    /**
     * Does this KeyStore type support a certain named curve?
     *
     * @param curveName The curve name to check for support.
     * @return True, if curve is supported
     */
    public boolean supportsNamedCurve(String curveName) {
        return EccUtil.isCurveAvailable(curveName, this);
    }

    /**
     * Resolve the supplied JCE name to a matching KeyStore type.
     *
     * @param jce JCE name
     * @return KeyStore type or null if none
     */
    public static KeyStoreType resolveJce(String jce) {
        for (KeyStoreType keyStoreType : values()) {
            if (jce.equals(keyStoreType.jce())) {
                return keyStoreType;
            }
        }

        return UNKNOWN;
    }

    /**
     * Get crypto file type.
     *
     * @return Crypto file type or null if KeyStore type is not file based
     */
    public CryptoFileType getCryptoFileType() {
        return cryptoFileType;
    }

    /**
     * @return the alias comparator
     */
    public Comparator<String> getAliasComparator() {
        return aliasComparator;
    }

    /**
     * Normalizes an alias for the key store type.
     *
     * @param alias The alias to normalize.
     * @return The normalized alias.
     */
    public String normalizeAlias(String alias) {
        return normalizer.apply(alias);
    }

    /**
     * Returns JCE name.
     *
     * @return JCE name
     */
    @Override
    public String toString() {
        return jce();
    }

    private static int compareCaseSensitive(String s1, String s2) {
        return s1.compareTo(s2);
    }

    private static int compareCaseInsensitive(String s1, String s2) {
        return s1.compareToIgnoreCase(s2);
    }

    private static String noop(String s) {
        return s;
    }

    private static String toLowerCase(String s) {
        return s != null ? s.toLowerCase() : null;
    }
}
