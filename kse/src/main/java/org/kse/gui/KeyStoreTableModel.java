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
package org.kse.gui;

import static org.kse.crypto.KeyType.SYMMETRIC;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.crypto.secretkey.SecretKeyUtil;
import org.kse.crypto.x509.KseX500NameStyle;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.table.ToolTipTableModel;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;
import org.kse.utilities.io.HexUtil;

/**
 * The table model used to display a KeyStore's entries sorted by alias name.
 */
public class KeyStoreTableModel extends ToolTipTableModel {
    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");
    private String[] columnNames;
    private Class<?>[] columnTypes;
    private Object[][] data = new Object[0][0];
    private KeyStoreHistory history;

    // This array of nulls is used by the constructor to initialize the
    // ToolTipTableModel that manages the tool tips. This reference must
    // not be changed when the user chooses to show or hide columns.
    // adjustColumns() will update the array elements with the correct
    // tool tip when the user chooses to show or hide columns. The number
    // of array elements must always match the total number of columns.
    private static final String[] COLUMN_TOOL_TIPS = new String[21];

    enum EntryType {
        /**
         * Type column value for a key pair entry
         */
        KEY_PAIR(res.getString("KeyStoreTableModel.KeyPairEntry")),

        /**
         * Type column value for a trusted certificate entry
         */
        TRUST_CERT(res.getString("KeyStoreTableModel.TrustCertEntry")),

        /**
         * Type column value for a key entry
         */
        KEY(res.getString("KeyStoreTableModel.KeyEntry"));

        private String text;

        EntryType(String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    enum Expiration {
        EXPIRED(res.getString("KeyStoreTableModel.Expired")),
        ALMOST_EXPIRED(res.getString("KeyStoreTableModel.AlmostExpired")),
        NOT_EXPIRED(res.getString("KeyStoreTableModel.NotExpired"));

        private String text;

        Expiration(String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    private KeyStoreTableColumns keyStoreTableColumns;
    private int nofColumns = 5;

    /**
     * Column for a property
     */
    private int expiryWarnDays = 0;
    private int iNameColumn = -1;
    private int iAlgorithmColumn = -1;
    private int iKeySizeColumn = -1;
    private int iCurveColumn = -1;
    private int iCertValidityStartColumn = -1;
    private int iCertExpiryColumn = -1;
    private int iLastModifiedColumn = -1;
    private int iAKIColumn = -1;
    private int iSKIColumn = -1;
    private int iIssuerDNColumn = -1;
    private int iSubjectDNColumn = -1;
    private int iIssuerCNColumn = -1;
    private int iSubjectCNColumn = -1;
    private int iIssuerOColumn = -1;
    private int iSubjectOColumn = -1;
    private int iSerialNumberHexColumn = -1;
    private int iSerialNumberDecColumn = -1;
    private int iFingerprintColumn = -1;

    /**
     * Construct a new KeyStoreTableModel with a variable layout.
     *
     * @param keyStoreTableColumns The key store table columns to display from preferences.
     * @param expiryWarnDays       The number of days for expiration warning from preferences.
     */
    public KeyStoreTableModel(KeyStoreTableColumns keyStoreTableColumns, int expiryWarnDays) {
        super(res, COLUMN_TOOL_TIPS);
        this.keyStoreTableColumns = keyStoreTableColumns;
        this.expiryWarnDays = expiryWarnDays;
        adjustColumns();
    }

    /**
     * Load the KeyStoreTableModel with the entries from a KeyStore.
     *
     * @param history KeyStore history
     * @throws GeneralSecurityException If a KeyStore problem occurs while accessing the KeyStore's
     *                                  entries
     * @throws CryptoException          If a crypto problem occurs while accessing the KeyStore's
     *                                  entries
     */
    public void load(KeyStoreHistory history) throws GeneralSecurityException, CryptoException {
        this.history = history;
        KeyStoreState currentState = history.getCurrentState();

        KseKeyStore keyStore = currentState.getKeyStore();
        KeyStoreType type = KeyStoreType.resolveJce(keyStore.getType());

        Enumeration<String> aliases = keyStore.aliases();

        TreeMap<String, String> sortedAliases = new TreeMap<>(type.getAliasComparator());

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!KeyStoreUtil.isSupportedEntryType(alias, keyStore)) {
                continue;
            }
            sortedAliases.put(alias, alias);
        }

        data = new Object[sortedAliases.size()][nofColumns];

        int i = 0;
        for (Iterator<Entry<String, String>> itr = sortedAliases.entrySet().iterator(); itr.hasNext(); i++) {
            String alias = itr.next().getKey();

            EntryType entryType = null;

            // Type column
            if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
                entryType = EntryType.TRUST_CERT;
            } else if (KeyStoreUtil.isKeyPairEntry(alias, keyStore)) {
                entryType = EntryType.KEY_PAIR;
            } else {
                entryType = EntryType.KEY;
            }

            data[i][0] = entryType;

            // Lock column - only applies to KeyStores types that actually support passwords for entries
            if ((entryType == EntryType.KEY_PAIR || entryType == EntryType.KEY) && type.hasEntryPasswords()) {
                if (currentState.getEntryPassword(alias) != null) {
                    data[i][1] = Boolean.FALSE; // Unlocked
                } else {
                    data[i][1] = Boolean.TRUE; // Locked
                }
            } else {
                data[i][1] = null; // Lock status does not apply
            }

            Expiration expiration;

            // Expiry status column
            Date expiry = getCertificateExpiry(alias, keyStore);
            ZonedDateTime now = ZonedDateTime.now(ZoneId.systemDefault());
            ZonedDateTime nowPlusExpiryWarnDays = now.plusDays(expiryWarnDays);
            if (expiry == null) {
                expiration = null; // No certExpiration - must be a key entry
            } else {
                ZonedDateTime expiryDateTime = expiry.toInstant().atZone(ZoneId.systemDefault());
                if (now.isAfter(expiryDateTime)) {
                    expiration = Expiration.EXPIRED;
                } else {
                    if (nowPlusExpiryWarnDays.isAfter(expiryDateTime)) {
                        expiration = Expiration.ALMOST_EXPIRED;
                    } else {
                        expiration = Expiration.NOT_EXPIRED;
                    }
                }
            }

            data[i][2] = expiration;

            if (iNameColumn > 0) {
                // Alias column
                data[i][iNameColumn] = alias;
            }

            KeyInfo keyInfo = getKeyInfo(alias, keyStore, currentState);

            if (keyInfo != null) {
                // Algorithm column
                if (iAlgorithmColumn > 0) {
                    data[i][iAlgorithmColumn] = getAlgorithmName(keyInfo);
                }

                // Key Size column
                if (iKeySizeColumn > 0) {
                    data[i][iKeySizeColumn] = keyInfo.getSize();
                }
                // EC curve column
                if (keyStoreTableColumns.getEnableCurve()) {
                    data[i][iCurveColumn] = keyInfo.getDetailedAlgorithm();
                }
            }
            if (iCertValidityStartColumn > 0) {
                data[i][iCertValidityStartColumn] = getCertificateValidityStart(alias, keyStore);
            }
            if (iCertExpiryColumn > 0) {
                data[i][iCertExpiryColumn] = expiry;
            }
            if (iLastModifiedColumn > 0) {
                // Modified date column - only applies to non-PKCS #11/#12 KeyStores
                if (!keyStore.getType().equals(KeyStoreType.PKCS12.jce()) &&
                    !keyStore.getType().equals(KeyStoreType.PKCS11.jce())) {
                    data[i][iLastModifiedColumn] = keyStore.getCreationDate(alias);
                } else {
                    data[i][iLastModifiedColumn] = null;
                }
            }
            if (iSubjectDNColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iSubjectDNColumn] = getCertificateSubjectDN(alias, keyStore);
                } else {
                    data[i][iSubjectDNColumn] = null;
                }
            }
            if (iIssuerDNColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iIssuerDNColumn] = getCertificateIssuerDN(alias, keyStore);
                } else {
                    data[i][iIssuerDNColumn] = null;
                }
            }
            if (iSerialNumberHexColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iSerialNumberHexColumn] = getCertificateSerialNumberHex(alias, keyStore);
                } else {
                    data[i][iSerialNumberHexColumn] = null;
                }
            }
            if (iSerialNumberDecColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iSerialNumberDecColumn] = getCertificateSerialNumberDec(alias, keyStore);
                } else {
                    data[i][iSerialNumberDecColumn] = null;
                }
            }
            if (iSubjectCNColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iSubjectCNColumn] = getCertificateSubjectCN(alias, keyStore);
                } else {
                    data[i][iSubjectCNColumn] = null;
                }
            }
            if (iIssuerCNColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iIssuerCNColumn] = getCertificateIssuerCN(alias, keyStore);
                } else {
                    data[i][iIssuerCNColumn] = null;
                }
            }
            if (iSubjectOColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iSubjectOColumn] = getCertificateSubjectO(alias, keyStore);
                } else {
                    data[i][iSubjectOColumn] = null;
                }
            }
            if (iIssuerOColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iIssuerOColumn] = getCertificateIssuerO(alias, keyStore);
                } else {
                    data[i][iIssuerOColumn] = null;
                }
            }
            if (iAKIColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iAKIColumn] = getCertificateAKI(alias, keyStore);
                } else {
                    data[i][iAKIColumn] = null;
                }
            }
            if (iSKIColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iSKIColumn] = getCertificateSKI(alias, keyStore);
                } else {
                    data[i][iSKIColumn] = null;
                }
            }
            if (iFingerprintColumn > 0) {
                if (entryType != EntryType.KEY) {
                    data[i][iFingerprintColumn] = getCertificateFingerprint(alias, keyStore,
                                                                            keyStoreTableColumns.getFingerprintAlg());
                } else {
                    data[i][iFingerprintColumn] = null;
                }
            }
        }

        fireTableDataChanged();
    }

    private Date getCertificateValidityStart(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
            return X509CertUtil.convertCertificate(keyStore.getCertificate(alias)).getNotBefore();
        } else {
            Certificate[] chain = keyStore.getCertificateChain(alias);

            if (chain == null) {
                return null; // Key entry - no validity start date
            }

            // Key pair - first certificate in chain will be for the private key
            X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
            return x509Chain[0].getNotBefore();
        }
    }

    private Date getCertificateExpiry(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
            return X509CertUtil.convertCertificate(keyStore.getCertificate(alias)).getNotAfter();
        } else {
            Certificate[] chain = keyStore.getCertificateChain(alias);

            if (chain == null) {
                // Key entry - no expiry date
                return null;
            }

            // Key pair - first certificate in chain will be for the private key
            X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
            if (expiryWarnDays < 1) {
                return x509Chain[0].getNotAfter();
            } else {
                Calendar cal = Calendar.getInstance();
                cal.set(9999, Calendar.FEBRUARY, 1);
                Date earliest = cal.getTime();
                for (X509Certificate x509Certificate : x509Chain) {
                    if (x509Certificate.getNotAfter().before(earliest)) {
                        earliest = x509Certificate.getNotAfter();
                    }
                }
                return earliest;
            }
        }
    }

    private KeyInfo getKeyInfo(String alias, KseKeyStore keyStore, KeyStoreState currentState)
            throws CryptoException, GeneralSecurityException {
        if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
            // Get key info from certificate
            X509Certificate cert = X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
            return KeyPairUtil.getKeyInfo(cert.getPublicKey());
        } else {
            Certificate[] chain = keyStore.getCertificateChain(alias);

            if (chain != null) {
                // Key pair - first certificate in chain will be for the private key
                X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));

                return KeyPairUtil.getKeyInfo(x509Chain[0].getPublicKey());
            } else {
                // Key entry - get key info if entry is unlocked
                if (currentState.getEntryPassword(alias) != null) {
                    char[] keyPassword = null;

                    keyPassword = currentState.getEntryPassword(alias).toCharArray();

                    Key key = keyStore.getKey(alias, keyPassword);
                    if (key instanceof SecretKey) {
                        return SecretKeyUtil.getKeyInfo((SecretKey) key);
                    } else if (key instanceof PrivateKey) {
                        return KeyPairUtil.getKeyInfo((PrivateKey) key);
                    } else if (key instanceof PublicKey) {
                        return KeyPairUtil.getKeyInfo((PublicKey) key);
                    }
                }
            }
        }

        return null;
    }

    private String getAlgorithmName(KeyInfo keyInfo) {
        String algorithm = keyInfo.getAlgorithm();

        if (keyInfo.getKeyType() == SYMMETRIC) {
            // Try and get friendly algorithm name for secret key
            SecretKeyType secretKeyType = SecretKeyType.resolveJce(algorithm);

            if (secretKeyType != null) {
                algorithm = secretKeyType.friendly();
            }
        }

        return algorithm;
    }

    private String getCertificateSubjectDN(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, keyStore);
        return X500NameUtils.x500PrincipalToX500Name(x509Cert.getSubjectX500Principal()).toString();
    }

    private String getCertificateIssuerDN(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, keyStore);
        return X500NameUtils.x500PrincipalToX500Name(x509Cert.getIssuerX500Principal()).toString();
    }

    private String getCertificateSerialNumberHex(String alias, KseKeyStore ks) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, ks);
        return X509CertUtil.getSerialNumberAsHex(x509Cert);
    }

    private String getCertificateSerialNumberDec(String alias, KseKeyStore ks) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, ks);
        return X509CertUtil.getSerialNumberAsDec(x509Cert);
    }

    private String getCertificateFingerprint(String alias, KseKeyStore ks, DigestType fingerprintAlg)
            throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, ks);
        return X509CertUtil.getFingerprint(x509Cert, fingerprintAlg);
    }

    private String getCertificateSubjectCN(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, keyStore);
        return X500NameUtils.extractCN(x509Cert.getSubjectX500Principal());
    }

    private String getCertificateIssuerCN(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, keyStore);
        return X500NameUtils.extractCN(x509Cert.getIssuerX500Principal());
    }

    private String getCertificateSKI(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, keyStore);
        try {
            byte[] skiValue = x509Cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            byte[] octets = DEROctetString.getInstance(skiValue).getOctets();
            byte[] skiBytes = SubjectKeyIdentifier.getInstance(octets).getKeyIdentifier();
            return HexUtil.getHexString(skiBytes);
        } catch (Exception e) {
            return "-";
        }
    }

    private String getCertificateAKI(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, keyStore);
        try {
            byte[] akiValue = x509Cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            byte[] octets = DEROctetString.getInstance(akiValue).getOctets();
            byte[] akiBytes = AuthorityKeyIdentifier.getInstance(octets).getKeyIdentifier();
            return HexUtil.getHexString(akiBytes);
        } catch (Exception e) {
            return "-";
        }
    }

    private String getCertificateSubjectO(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, keyStore);
        X500Name subject = X500NameUtils.x500PrincipalToX500Name(x509Cert.getSubjectX500Principal());
        return X500NameUtils.getRdn(subject, KseX500NameStyle.O);
    }

    private String getCertificateIssuerO(String alias, KseKeyStore keyStore) throws CryptoException, KeyStoreException {
        X509Certificate x509Cert = getCertificate(alias, keyStore);
        X500Name issuer = X500NameUtils.x500PrincipalToX500Name(x509Cert.getIssuerX500Principal());
        return X500NameUtils.getRdn(issuer, KseX500NameStyle.O);
    }

    private X509Certificate getCertificate(String alias, KseKeyStore keyStore) throws KeyStoreException, CryptoException {
        X509Certificate x509Cert = null;
        if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
            x509Cert = X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
        } else {
            Certificate[] chain = keyStore.getCertificateChain(alias);
            if (chain == null) {
                return null;
            }
            // Key pair - first certificate in chain will be for the private key
            X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
            x509Cert = x509Chain[0];
        }
        return x509Cert;
    }

    private void adjustColumns() {
        nofColumns = 3 + keyStoreTableColumns.getNofColumns();

        // remove all columns before possibly enabling them
        iNameColumn = -1;
        iAlgorithmColumn = -1;
        iKeySizeColumn = -1;
        iCurveColumn = -1;
        iCertValidityStartColumn = -1;
        iCertExpiryColumn = -1;
        iLastModifiedColumn = -1;
        iAKIColumn = -1;
        iSKIColumn = -1;
        iIssuerDNColumn = -1;
        iSubjectDNColumn = -1;
        iIssuerCNColumn = -1;
        iSubjectCNColumn = -1;
        iIssuerOColumn = -1;
        iSubjectOColumn = -1;
        iSerialNumberHexColumn = -1;
        iSerialNumberDecColumn = -1;

        columnNames = new String[nofColumns];
        columnTypes = new Class[nofColumns];
        columnNames[0] = res.getString("KeyStoreTableModel.TypeColumn");
        columnTypes[0] = String.class;
        COLUMN_TOOL_TIPS[0] = "KeyStoreTableModel.TypeColumn.tooltip";
        columnNames[1] = res.getString("KeyStoreTableModel.LockStatusColumn");
        columnTypes[1] = Boolean.class;
        COLUMN_TOOL_TIPS[1] = "KeyStoreTableModel.LockStatusColumn.tooltip";
        columnNames[2] = res.getString("KeyStoreTableModel.CertExpiryStatusColumn");
        columnTypes[2] = Integer.class;
        COLUMN_TOOL_TIPS[2] = "KeyStoreTableModel.CertExpiryStatusColumn.tooltip";

        for (int col = 3; col < nofColumns; col++) {
            if (col == keyStoreTableColumns.colIndexEntryName()) {
                columnNames[col] = res.getString("KeyStoreTableModel.NameColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.NameColumn.tooltip";
                iNameColumn = col;
            } else if (col == keyStoreTableColumns.colIndexAlgorithm()) {
                columnNames[col] = res.getString("KeyStoreTableModel.AlgorithmColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.AlgorithmColumn.tooltip";
                iAlgorithmColumn = col;
            } else if (col == keyStoreTableColumns.colIndexKeySize()) {
                columnNames[col] = res.getString("KeyStoreTableModel.KeySizeColumn");
                columnTypes[col] = Integer.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.KeySizeColumn.tooltip";
                iKeySizeColumn = col;
            } else if (col == keyStoreTableColumns.colIndexCurve()) {
                columnNames[col] = res.getString("KeyStoreTableModel.CurveColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.CurveColumn.tooltip";
                iCurveColumn = col;
            } else if (col == keyStoreTableColumns.colIndexCertificateValidityStart()) {
                columnNames[col] = res.getString("KeyStoreTableModel.CertValidityStartColumn");
                columnTypes[col] = Date.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.CertValidityStartColumn.tooltip";
                iCertValidityStartColumn = col;
            } else if (col == keyStoreTableColumns.colIndexCertificateExpiry()) {
                columnNames[col] = res.getString("KeyStoreTableModel.CertExpiryColumn");
                columnTypes[col] = Date.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.CertExpiryColumn.tooltip";
                iCertExpiryColumn = col;
            } else if (col == keyStoreTableColumns.colIndexLastModified()) {
                columnNames[col] = res.getString("KeyStoreTableModel.LastModifiedColumn");
                columnTypes[col] = Date.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.LastModifiedColumn.tooltip";
                iLastModifiedColumn = col;
            } else if (col == keyStoreTableColumns.colIndexAKI()) {
                columnNames[col] = res.getString("KeyStoreTableModel.AKIColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.AKIColumn.tooltip";
                iAKIColumn = col;
            } else if (col == keyStoreTableColumns.colIndexSKI()) {
                columnNames[col] = res.getString("KeyStoreTableModel.SKIColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.SKIColumn.tooltip";
                iSKIColumn = col;
            } else if (col == keyStoreTableColumns.colIndexIssuerDN()) {
                columnNames[col] = res.getString("KeyStoreTableModel.IssuerDNColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.IssuerDNColumn.tooltip";
                iIssuerDNColumn = col;
            } else if (col == keyStoreTableColumns.colIndexSubjectDN()) {
                columnNames[col] = res.getString("KeyStoreTableModel.SubjectDNColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.SubjectDNColumn.tooltip";
                iSubjectDNColumn = col;
            } else if (col == keyStoreTableColumns.colIndexIssuerCN()) {
                columnNames[col] = res.getString("KeyStoreTableModel.IssuerCNColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.IssuerCNColumn.tooltip";
                iIssuerCNColumn = col;
            } else if (col == keyStoreTableColumns.colIndexSubjectCN()) {
                columnNames[col] = res.getString("KeyStoreTableModel.SubjectCNColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.SubjectCNColumn.tooltip";
                iSubjectCNColumn = col;
            } else if (col == keyStoreTableColumns.colIndexIssuerO()) {
                columnNames[col] = res.getString("KeyStoreTableModel.IssuerOColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.IssuerOColumn.tooltip";
                iIssuerOColumn = col;
            } else if (col == keyStoreTableColumns.colIndexSubjectO()) {
                columnNames[col] = res.getString("KeyStoreTableModel.SubjectOColumn");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.SubjectOColumn.tooltip";
                iSubjectOColumn = col;
            } else if (col == keyStoreTableColumns.colIndexSerialNumberHex()) {
                columnNames[col] = res.getString("KeyStoreTableModel.SerialNumberHex");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = null;
                iSerialNumberHexColumn = col;
            } else if (col == keyStoreTableColumns.colIndexSerialNumberDec()) {
                columnNames[col] = res.getString("KeyStoreTableModel.SerialNumberDec");
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = null;
                iSerialNumberDecColumn = col;
            } else if (col == keyStoreTableColumns.colIndexFingerprint()) {
                columnNames[col] = MessageFormat.format(res.getString("KeyStoreTableModel.Fingerprint"),
                                                        keyStoreTableColumns.getFingerprintAlg());
                columnTypes[col] = String.class;
                COLUMN_TOOL_TIPS[col] = "KeyStoreTableModel.FingerprintColumn.tooltip";
                iFingerprintColumn = col;
            }
        }
    }

    /**
     * Get the number of columns in the table.
     *
     * @return The number of columns
     */
    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    /**
     * Get the number of rows in the table.
     *
     * @return The number of rows
     */
    @Override
    public int getRowCount() {
        return data.length;
    }

    /**
     * Get the name of the column at the given position.
     *
     * @param col The column position
     * @return The column name
     */
    @Override
    public String getColumnName(int col) {
        return columnNames[col];
    }

    /**
     * Get the cell value at the given row and column position.
     *
     * @param row The row position
     * @param col The column position
     * @return The cell value
     */
    @Override
    public Object getValueAt(int row, int col) {
        return data[row][col];
    }

    /**
     * Get the class of the values at the provided column.
     *
     * @param col The column position
     * @return The column cells' class
     */
    @Override
    public Class<?> getColumnClass(int col) {
        return columnTypes[col];
    }

    /**
     * Is the cell at the given row and column position editable?
     *
     * @param row The row position
     * @param col The column position
     * @return True if the cell is editable, false otherwise
     */
    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    KeyStoreHistory getHistory() {
        return history;
    }
}
