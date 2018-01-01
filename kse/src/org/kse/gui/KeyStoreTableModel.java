/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.crypto.SecretKey;
import javax.swing.table.AbstractTableModel;

import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.crypto.secretkey.SecretKeyUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * The table model used to display a KeyStore's entries sorted by alias name.
 *
 */
public class KeyStoreTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");
	private String[] columnNames;
	private Object[][] data;

	/** Type column value for a key pair entry */
	public static final String KEY_PAIR_ENTRY = res.getString("KeyStoreTableModel.KeyPairEntry");

	/** Type column value for a trusted certificate entry */
	public static final String TRUST_CERT_ENTRY = res.getString("KeyStoreTableModel.TrustCertEntry");

	/** Type column value for a key entry */
	public static final String KEY_ENTRY = res.getString("KeyStoreTableModel.KeyEntry");

	/**
	 * Construct a new KeyStoreTableModel.
	 */
	public KeyStoreTableModel() {
		columnNames = new String[8];
		columnNames[0] = res.getString("KeyStoreTableModel.TypeColumn");
		columnNames[1] = res.getString("KeyStoreTableModel.LockStatusColumn");
		columnNames[2] = res.getString("KeyStoreTableModel.CertExpiryStatusColumn");
		columnNames[3] = res.getString("KeyStoreTableModel.NameColumn");
		columnNames[4] = res.getString("KeyStoreTableModel.AlgorithmColumn");
		columnNames[5] = res.getString("KeyStoreTableModel.KeySizeColumn");
		columnNames[6] = res.getString("KeyStoreTableModel.CertExpiryColumn");
		columnNames[7] = res.getString("KeyStoreTableModel.LastModifiedColumn");

		data = new Object[0][0];
	}

	/**
	 * Load the KeyStoreTableModel with the entries from a KeyStore.
	 *
	 * @param history
	 *            KeyStore history
	 * @throws GeneralSecurityException
	 *             If a KeyStore problem occurs while accessing the KeyStore's
	 *             entries
	 * @throws CryptoException
	 *             If a crypto problem occurs while accessing the KeyStore's
	 *             entries
	 */
	public void load(KeyStoreHistory history) throws GeneralSecurityException, CryptoException {
		KeyStoreState currentState = history.getCurrentState();

		KeyStore keyStore = currentState.getKeyStore();
		KeyStoreType type = KeyStoreType.resolveJce(keyStore.getType());

		Enumeration<String> aliases = keyStore.aliases();

		TreeMap<String, String> sortedAliases = new TreeMap<String, String>(new AliasComparator());

		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (!KeyStoreUtil.isSupportedEntryType(alias, keyStore)) {
				continue;
			}
			sortedAliases.put(alias, alias);
		}

		data = new Object[sortedAliases.size()][8];

		int i = 0;
		for (Iterator<Entry<String, String>> itr = sortedAliases.entrySet().iterator(); itr.hasNext(); i++) {
			String alias = itr.next().getKey();

			String entryType = null;

			// Type column
			if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
				entryType = TRUST_CERT_ENTRY;
			} else if (KeyStoreUtil.isKeyPairEntry(alias, keyStore)) {
				entryType = KEY_PAIR_ENTRY;
			} else {
				entryType = KEY_ENTRY;
			}

			data[i][0] = entryType;

			// Lock column - only applies to KeyStores types that actually support passwords for entries
			if ((entryType.equals(KEY_PAIR_ENTRY) || entryType.equals(KEY_ENTRY)) && type.hasEntryPasswords()) {
				if (currentState.getEntryPassword(alias) != null) {
					data[i][1] = Boolean.FALSE; // Unlocked
				} else {
					data[i][1] = Boolean.TRUE; // Locked
				}
			} else {
				data[i][1] = null; // Lock status does not apply
			}

			// Expiry status column
			Date expiry = getCertificateExpiry(alias, keyStore);

			if (expiry == null) {
				data[i][2] = null; // No expiry - must be a key entry
			} else if (new Date().after(expiry)) {
				data[i][2] = Boolean.TRUE; // Expired
			} else {
				data[i][2] = Boolean.FALSE; // Not expired
			}

			// Alias column
			data[i][3] = alias;

			KeyInfo keyInfo = getKeyInfo(alias, keyStore, currentState);

			if (keyInfo != null) {
				// Algorithm column
				data[i][4] = getAlgorithmName(keyInfo);

				// Key Size column
				data[i][5] = keyInfo.getSize();
			}

			// Expiry date column
			if (expiry != null) {
				data[i][6] = expiry;
			} else {
				data[i][6] = null; // No expiry date - must be a key entry
			}

			// Modified date column - only applies to non-PKCS #11/#12 KeyStores
			if (!keyStore.getType().equals(KeyStoreType.PKCS12.jce())
					&& !keyStore.getType().equals(KeyStoreType.PKCS11.jce())) {
				data[i][7] = keyStore.getCreationDate(alias);
			} else {
				data[i][7] = null;
			}
		}

		fireTableDataChanged();
	}

	private Date getCertificateExpiry(String alias, KeyStore keyStore) throws CryptoException, KeyStoreException {
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

			return x509Chain[0].getNotAfter();
		}
	}

	private KeyInfo getKeyInfo(String alias, KeyStore keyStore, KeyStoreState currentState) throws CryptoException,
	GeneralSecurityException {
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
	 * @param col
	 *            The column position
	 * @return The column name
	 */
	@Override
	public String getColumnName(int col) {
		return columnNames[col];
	}

	/**
	 * Get the cell value at the given row and column position.
	 *
	 * @param row
	 *            The row position
	 * @param col
	 *            The column position
	 * @return The cell value
	 */
	@Override
	public Object getValueAt(int row, int col) {
		return data[row][col];
	}

	/**
	 * Get the class of the values at the provided column.
	 *
	 * @param col
	 *            The column position
	 * @return The column cells' class
	 */
	@Override
	public Class<?> getColumnClass(int col) {
		switch (col) {
		case 0:
			return String.class;
		case 1:
			return Boolean.class;
		case 2:
			return Boolean.class;
		case 3:
			return String.class;
		case 4:
			return String.class;
		case 5:
			return Integer.class;
		default:
			return Date.class;
		}
	}

	/**
	 * Is the cell at the given row and column position editable?
	 *
	 * @param row
	 *            The row position
	 * @param col
	 *            The column position
	 * @return True if the cell is editable, false otherwise
	 */
	@Override
	public boolean isCellEditable(int row, int col) {
		return false;
	}

	private class AliasComparator implements Comparator<String> {
		@Override
		public int compare(String name1, String name2) {
			return name1.compareToIgnoreCase(name2);
		}
	}
}
