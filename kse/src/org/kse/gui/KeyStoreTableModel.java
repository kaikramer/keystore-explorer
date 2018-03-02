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
import java.util.Calendar;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.crypto.SecretKey;
import javax.swing.table.AbstractTableModel;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.crypto.secretkey.SecretKeyUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KeyStoreTableColumns;
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
	private Class[] columnTypes;
	private Object[][] data;

	/** Type column value for a key pair entry */
	public static final String KEY_PAIR_ENTRY = res.getString("KeyStoreTableModel.KeyPairEntry");

	/** Type column value for a trusted certificate entry */
	public static final String TRUST_CERT_ENTRY = res.getString("KeyStoreTableModel.TrustCertEntry");

	/** Type column value for a key entry */
	public static final String KEY_ENTRY = res.getString("KeyStoreTableModel.KeyEntry");

	private KeyStoreTableColumns keyStoreTableColumns = new KeyStoreTableColumns();
	private int nofColumns = 5;
	/** Column for a property */
	private static int expiryWarnDays = 0;
	private static int iNameColumn = -1;
	private static int iAlgorithmColumn = -1;
	private static int iKeySizeColumn = -1;
	private static int iCurveColumn = -1;
	private static int iCertExpiryColumn = -1;
	private static int iLastModifiedColumn = -1;
	private static int iAKIColumn = -1;
	private static int iSKIColumn = -1;
	private static int iIssuerDNColumn = -1;
	private static int iSubjectDNColumn = -1;
	private static int iIssuerCNColumn = -1;
	private static int iSubjectCNColumn = -1;
	private static int iIssuerOColumn = -1;
	private static int iSubjectOColumn = -1;
	/**
	 * Construct a new KeyStoreTableModel with a variable layout.
	 */
	public KeyStoreTableModel(KeyStoreTableColumns keyStoreTableColumnsParm) {
		keyStoreTableColumns = keyStoreTableColumnsParm;
		nofColumns = 3+keyStoreTableColumns.getNofColumns();
		expiryWarnDays = keyStoreTableColumns.getExpiryWarnDays();
		int col = 2;
		columnNames = new String[nofColumns];
		columnTypes = new Class[nofColumns];
		columnNames[0] = res.getString("KeyStoreTableModel.TypeColumn");
		columnTypes[0] = String.class;
		columnNames[1] = res.getString("KeyStoreTableModel.LockStatusColumn");
		columnTypes[1] = Boolean.class;
		columnNames[2] = res.getString("KeyStoreTableModel.CertExpiryStatusColumn");
		columnTypes[2] = Integer.class;
		for (col=3;col<nofColumns;col++)
		{
			if (col == keyStoreTableColumns.colEntryName())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.NameColumn");
				columnTypes[col] = String.class;
				iNameColumn = col;
			}

			if (col == keyStoreTableColumns.colAlgorithm())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.AlgorithmColumn");
				columnTypes[col] = String.class;
				iAlgorithmColumn = col;
				
			}
			if (col == keyStoreTableColumns.colKeySize())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.KeySizeColumn");
				columnTypes[col] =  Integer.class;
				iKeySizeColumn = col;
			}
			if (col == keyStoreTableColumns.colCurve())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.CurveColumn");
				columnTypes[col] = String.class;
				iCurveColumn = col;
				
			}
			if (col == keyStoreTableColumns.colCertificateExpiry())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.CertExpiryColumn");
				columnTypes[col] = Date.class;
				iCertExpiryColumn = col;
			}
			if (col == keyStoreTableColumns.colLastModified())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.LastModifiedColumn");
				columnTypes[col] = Date.class;
				iLastModifiedColumn = col;
				
			}
			if (col == keyStoreTableColumns.colAKI())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.AKIColumn");
				columnTypes[col] = String.class;
				iAKIColumn = col;
				
			}
			if (col == keyStoreTableColumns.colSKI())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.SKIColumn");
				columnTypes[col] = String.class;
				iSKIColumn = col;
			}
			if (col == keyStoreTableColumns.colIssuerDN())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.IssuerDNColumn");
				columnTypes[col] = String.class;
				iIssuerDNColumn = col;
			}
			if (col == keyStoreTableColumns.colSubjectDN())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.SubjectDNColumn");
				columnTypes[col] = String.class;
				iSubjectDNColumn = col;
			}
			if (col == keyStoreTableColumns.colIssuerCN())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.IssuerCNColumn");
				columnTypes[col] = String.class;
				iIssuerCNColumn = col;
			}
			if (col == keyStoreTableColumns.colSubjectCN())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.SubjectCNColumn");
				columnTypes[col] = String.class;
				iSubjectCNColumn = col;
			}
			if (col == keyStoreTableColumns.colIssuerO())
			{
				columnNames[col] = res.getString("KeyStoreTableModel.IssuerOColumn");
				columnTypes[col] = String.class;
				iIssuerOColumn = col;
			}
			if (col == keyStoreTableColumns.colSubjectO())
			{
				columnNames[++col] = res.getString("KeyStoreTableModel.SubjectOColumn");
				columnTypes[col] = String.class;
				iSubjectOColumn = col;
			}
		}
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

		data = new Object[sortedAliases.size()][nofColumns];

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

			// Lock column - only applies to KeyStores types that actually
			// support passwords for entries
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
			Calendar c = Calendar.getInstance();
			Calendar a = Calendar.getInstance();
			c.setTime(new Date()); // Now use today date.
			a.setTime(new Date()); // Now use today date.
			a.add(Calendar.DATE, expiryWarnDays); // Adding warning interval
			if (expiry == null) {
				data[i][2] = null; // No expiry - must be a key entry
			} else {
				if (expiry.before(c.getTime())) {
					data[i][2] = 2; // Expired
				} else {
					if (expiry.before(a.getTime())) {
						data[i][2] = 1; // Almost expired
					} else {
						data[i][2] = 0; // Not expired
					}
				}
			}

			if (iNameColumn>0) {
			// Alias column
				data[i][iNameColumn] = alias;
			}

			KeyInfo keyInfo = getKeyInfo(alias, keyStore, currentState);

			if (keyInfo != null) {
				// Algorithm column
				if (iAlgorithmColumn>0) {
					data[i][iAlgorithmColumn] = getAlgorithmName(keyInfo);
				}

				// Key Size column
				if (iKeySizeColumn>0) {
					data[i][iKeySizeColumn] = keyInfo.getSize();
			}
				// Key Size column
				if (keyStoreTableColumns.getEnableCurve()) {
					data[i][iCurveColumn] = keyInfo.getDetailedAlgorithm();
				}
			}
			if (iCertExpiryColumn>0) {
			// Expiry date column
			if (expiry != null) {

					data[i][iCertExpiryColumn] = expiry;
			} else {
					data[i][iCertExpiryColumn] = null; // No expiry date - must
														// be a key entry
				}
			}
			if (iLastModifiedColumn>0) {
				// Modified date column - only applies to non-PKCS #11/#12
				// KeyStores
			if (!keyStore.getType().equals(KeyStoreType.PKCS12.jce())
					&& !keyStore.getType().equals(KeyStoreType.PKCS11.jce())) {
					data[i][iLastModifiedColumn] = keyStore.getCreationDate(alias);
			} else {
					data[i][iLastModifiedColumn] = null;
				}
			}
			if (iSubjectDNColumn>0) {
				if (entryType != KEY_ENTRY) {
					data[i][iSubjectDNColumn] = getCertificateSubjectDN( alias, keyStore) ;
				} else {
					data[i][iSubjectDNColumn] = null; 
				}
			}
			if (iIssuerDNColumn>0) {
				if (entryType != KEY_ENTRY) { 
					data[i][iIssuerDNColumn] = getCertificateIssuerDN( alias, keyStore) ;
				} else {
					data[i][iIssuerDNColumn] = null; 
				}
			}
			if (iSubjectCNColumn>0) {
				if (entryType != KEY_ENTRY) { // assume a certificate
					data[i][iSubjectCNColumn] = getCertificateSubjectCN( alias, keyStore) ;
				} else {
					data[i][iSubjectCNColumn] = null; 
				}
			}
			if (iIssuerCNColumn>0) {
				if (entryType != KEY_ENTRY) { // assume a certificate
					data[i][iIssuerCNColumn] = getCertificateIssuerCN( alias, keyStore) ;
				} else {
					data[i][iIssuerCNColumn] = null; 
				}
			}
			if (iSubjectOColumn>0) {
				if (entryType != KEY_ENTRY) { // assume a certificate
					data[i][iSubjectOColumn] = getCertificateSubjectO( alias, keyStore) ;
				} else {
					data[i][iSubjectOColumn] = null; 
				}
			}
			if (iIssuerOColumn>0) {
				if (entryType != KEY_ENTRY) { // assume a certificate
					data[i][iIssuerOColumn] = getCertificateIssuerO( alias, keyStore) ;
				} else {
					data[i][iIssuerOColumn] = null; 
				}
			}
			if (iAKIColumn>0) {
				if (entryType != KEY_ENTRY) { // assume a certificate
					data[i][iAKIColumn] = getCertificateAKI( alias, keyStore) ;
				} else {
					data[i][iAKIColumn] = null; 
				}
			}
			if (iSKIColumn>0) {
				if (entryType != KEY_ENTRY) { // assume a certificate
					data[i][iSKIColumn] = getCertificateSKI( alias, keyStore) ;
				} else {
					data[i][iSKIColumn] = null; 
				}
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
			if (expiryWarnDays < 1)
			{
			return x509Chain[0].getNotAfter();
		}
			else
			{
				Date earliest = new Date();
				earliest.setYear(9998);
				for (int i=0;i<x509Chain.length;i++)
				{
					if (x509Chain[i].getNotAfter().before(earliest))
						earliest = x509Chain[i].getNotAfter();
				}
				return earliest;
	}
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
	private String getCertificateSubjectDN(String alias, KeyStore keyStore) throws CryptoException, KeyStoreException {
		if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
			return X509CertUtil.convertCertificate(keyStore.getCertificate(alias)).getSubjectDN().getName();
		} else {
			Certificate[] chain = keyStore.getCertificateChain(alias);
			if (chain == null) {
				return null;
			}
			// Key pair - first certificate in chain will be for the private key
			X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
			return x509Chain[0].getSubjectDN().getName();
		}
	}
	private String getCertificateIssuerDN(String alias, KeyStore keyStore) throws CryptoException, KeyStoreException {
		if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
			return X509CertUtil.convertCertificate(keyStore.getCertificate(alias)).getIssuerDN().getName();
		} else {
			Certificate[] chain = keyStore.getCertificateChain(alias);
			if (chain == null) {
				return null;
			}
			// Key pair - first certificate in chain will be for the private key
			X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
			return x509Chain[0].getIssuerDN().getName();
		}
	}
	private String getCertificateSubjectCN(String alias, KeyStore keyStore) throws CryptoException, KeyStoreException {
		X509Certificate x509Cert = null;
		if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
			x509Cert= X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
		} else {
			Certificate[] chain = keyStore.getCertificateChain(alias);
			if (chain == null) {
				return null;
			}
			// Key pair - first certificate in chain will be for the private key
			X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
			x509Cert = x509Chain[0];
		}
		X500Name subject;
		try {
			subject = new JcaX509CertificateHolder(x509Cert).getSubject();
			RDN cn = subject.getRDNs(BCStyle.CN)[0];
			return ((ASN1String) cn.getFirst().getValue()).getString();
		} catch (Exception e) {
			return "";
		}
	}

	private String getCertificateIssuerCN(String alias, KeyStore keyStore) throws CryptoException, KeyStoreException {
		X509Certificate x509Cert = null;
		if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
			x509Cert= X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
		} else {
			Certificate[] chain = keyStore.getCertificateChain(alias);
			if (chain == null) {
				return null;
			}
			// Key pair - first certificate in chain will be for the private key
			X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
			x509Cert = x509Chain[0];
		}
		try {
			RDN cn = new JcaX509CertificateHolder(x509Cert).getIssuer().getRDNs(BCStyle.CN)[0];
			return ((ASN1String) cn.getFirst().getValue()).getString();
		} catch (Exception e) {
			return "";
		}
	}
	
	private String getCertificateAKI(String alias, KeyStore keyStore) throws CryptoException, KeyStoreException {
		X509Certificate x509Cert = null;
		if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
			x509Cert= X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
		} else {
			Certificate[] chain = keyStore.getCertificateChain(alias);
			if (chain == null) {
				return null;
			}
			// Key pair - first certificate in chain will be for the private key
			X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
			x509Cert = x509Chain[0];
		}
		try {
			String aki = DatatypeConverter.printHexBinary(x509Cert.getExtensionValue("2.5.29.35"));
			return aki.substring(12); // remove object header 041830168014
		} catch (Exception e) {
			return "-";
		}
	}
	
	private String getCertificateSKI(String alias, KeyStore keyStore) throws CryptoException, KeyStoreException {
		X509Certificate x509Cert = null;
		if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
			x509Cert= X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
		} else {
			Certificate[] chain = keyStore.getCertificateChain(alias);
			if (chain == null) {
				return null;
			}
			// Key pair - first certificate in chain will be for the private key
			X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
			x509Cert = x509Chain[0];
		}
		try {
			String ski = DatatypeConverter.printHexBinary(x509Cert.getExtensionValue("2.5.29.14"));
			return ski.substring(8); // remove object header 04160414		
		} catch (Exception e) {
			return "-";
		}
	}
	
	private String getCertificateSubjectO(String alias, KeyStore keyStore) throws CryptoException, KeyStoreException {
		X509Certificate x509Cert = null;
		if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
			x509Cert= X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
		} else {
			Certificate[] chain = keyStore.getCertificateChain(alias);
			if (chain == null) {
				return null;
			}
			// Key pair - first certificate in chain will be for the private key
			X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
			x509Cert = x509Chain[0];
		}
		X500Name subject;
		try {
			subject = new JcaX509CertificateHolder(x509Cert).getSubject();
			RDN cn = subject.getRDNs(BCStyle.O)[0];
			if (cn.size()>0)
			    return ((ASN1String) cn.getFirst().getValue()).getString();
			else
				return "";
		} catch (Exception e) {
			return "";
		}
	}
	
	private String getCertificateIssuerO(String alias, KeyStore keyStore) throws CryptoException, KeyStoreException {
		X509Certificate x509Cert = null;
		if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
			x509Cert= X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
		} else {
			Certificate[] chain = keyStore.getCertificateChain(alias);
			if (chain == null) {
				return null;
			}
			// Key pair - first certificate in chain will be for the private key
			X509Certificate[] x509Chain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(chain));
			x509Cert = x509Chain[0];
		}
		try {
			RDN cn = new JcaX509CertificateHolder(x509Cert).getIssuer().getRDNs(BCStyle.O)[0];
			if (cn.size()>0)
			    return ((ASN1String) cn.getFirst().getValue()).getString();
			else
				return "";
		} catch (Exception e) {
			return "";
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
		return columnTypes[col];
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

	public KeyStoreTableColumns getKeyStoreTableColumns() {
		return keyStoreTableColumns;
	}

	public void setKeyStoreTableColumns(KeyStoreTableColumns keyStoreTableColumns) {
		this.keyStoreTableColumns = keyStoreTableColumns;
	}

	private class AliasComparator implements Comparator<String> {
		@Override
		public int compare(String name1, String name2) {
			return name1.compareToIgnoreCase(name2);
		}
	}
}
