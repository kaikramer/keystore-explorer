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
package org.kse.crypto.x509;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.cert.X509Extension;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;

/**
 * Holds a set of X.509 extensions.
 *
 */
public class X509ExtensionSet implements X509Extension, Cloneable, Serializable {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");

	private Map<String, byte[]> criticalExtensions = new HashMap<String, byte[]>();
	private Map<String, byte[]> nonCriticalExtensions = new HashMap<String, byte[]>();

	private static final long FILE_MAGIC_NUMBER = 0x47911131;
	private static final int FILE_VERSION = 1;

	/**
	 * Default constructor
	 */
	public X509ExtensionSet() {
	}

	/**
	 * Creates an X509ExtensionSet object from the extensions in the ASN1 sequence.
	 *
	 * @param extensions Sequence with extensions.
	 */
	public X509ExtensionSet(ASN1Sequence extensions) {

		ASN1Encodable[] asn1Encodables = extensions.toArray();

		for (int i = 0; i < asn1Encodables.length; i++) {
			ASN1Encodable asn1Encodable = asn1Encodables[i];
			Extension ext = Extension.getInstance(asn1Encodable);
			if (ext != null) {
				try {
					addExtension(ext.getExtnId().toString(), ext.isCritical(), ext.getExtnValue().getEncoded());
				} catch (IOException e) {
					// ignore exception from getEncoded()
				}
			}
		}
	}

	/**
	 * Add an extension to the set. Any existing extension with the same oid
	 * will be removed in preference of this one.
	 *
	 * @param oid
	 *            X509Extension object identifier
	 * @param isCritical
	 *            Is extension critical?
	 * @param value
	 *            X509Extension as DER-encoded OCTET STRING
	 */
	public void addExtension(String oid, boolean isCritical, byte[] value) {
		removeExtension(oid);

		if (isCritical) {
			criticalExtensions.put(oid, value);
		} else {
			nonCriticalExtensions.put(oid, value);
		}
	}

	/**
	 * Remove an extension from the set.
	 *
	 * @param oid
	 *            X509Extension object identifier
	 */
	public void removeExtension(String oid) {
		if (criticalExtensions.containsKey(oid)) {
			criticalExtensions.remove(oid);
		} else if (nonCriticalExtensions.containsKey(oid)) {
			nonCriticalExtensions.remove(oid);
		}
	}

	/**
	 * Get critical extensions OIDs.
	 *
	 * @return OIDs
	 */
	@Override
	public Set<String> getCriticalExtensionOIDs() {
		return criticalExtensions.keySet();
	}

	/**
	 * Get non-critical extensions OIDs.
	 *
	 * @return OIDs
	 */
	@Override
	public Set<String> getNonCriticalExtensionOIDs() {
		return nonCriticalExtensions.keySet();
	}

	/**
	 * Get extension value for OID.
	 *
	 * @param oid
	 *            OID of extension
	 * @return Value or null if no such extension
	 */
	@Override
	public byte[] getExtensionValue(String oid) {
		if (criticalExtensions.containsKey(oid)) {
			return criticalExtensions.get(oid);
		} else if (nonCriticalExtensions.containsKey(oid)) {
			return nonCriticalExtensions.get(oid);
		}

		return null;
	}

	/**
	 * Toggle criticality of extension.
	 *
	 * @param oid
	 *            OID of extension
	 */
	public void toggleExtensionCriticality(String oid) {
		if (criticalExtensions.containsKey(oid)) {
			byte[] value = criticalExtensions.remove(oid);
			nonCriticalExtensions.put(oid, value);
		} else if (nonCriticalExtensions.containsKey(oid)) {
			byte[] value = nonCriticalExtensions.remove(oid);
			criticalExtensions.put(oid, value);
		}
	}

	/**
	 * 'Unsupported' has no meaning in this context.
	 *
	 * @return Always false.
	 */
	@Override
	public boolean hasUnsupportedCriticalExtension() {
		return false;
	}

	@Override
	@SuppressWarnings("unchecked")
	public Object clone() {
		try {
			X509ExtensionSet x509ExtensionSet = (X509ExtensionSet) super.clone();
			x509ExtensionSet.criticalExtensions = (HashMap<String, byte[]>) ((HashMap<String, byte[]>) criticalExtensions)
					.clone();
			x509ExtensionSet.nonCriticalExtensions = (HashMap<String, byte[]>) ((HashMap<String, byte[]>) nonCriticalExtensions)
					.clone();
			return x509ExtensionSet;
		} catch (CloneNotSupportedException ex) {
			// This shouldn't happen as we are Cloneable
			throw new RuntimeException(ex);
		}
	}

	/**
	 * Load X.509 extension set.
	 *
	 * @param is
	 *            Stream to load from
	 * @return X.509 extension set
	 * @throws X509ExtensionSetLoadException
	 *             If stream contents are not a valid X.509 extension set
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public static X509ExtensionSet load(InputStream is) throws X509ExtensionSetLoadException, IOException {
		try (DataInputStream dis = new DataInputStream(is)) {

			long magicNumber = dis.readLong();
			if (magicNumber != FILE_MAGIC_NUMBER) {
				throw new X509ExtensionSetLoadException(
						res.getString("NoLoadX509ExtensionSet.BadMagicNumber.exception.message"));
			}

			int version = dis.readInt();
			if (version != FILE_VERSION) {
				throw new X509ExtensionSetLoadException(
						res.getString("NoLoadX509ExtensionSet.WrongVersion.exception.message"));
			}

			X509ExtensionSet x509ExtensionSet = new X509ExtensionSet();
			x509ExtensionSet.criticalExtensions = loadExtensions(dis);
			x509ExtensionSet.nonCriticalExtensions = loadExtensions(dis);

			return x509ExtensionSet;
		} catch (EOFException ex) {
			throw new X509ExtensionSetLoadException(
					res.getString("NoLoadX509ExtensionSet.NotEnoughBytes.exception.message"));
		}
	}

	private static Map<String, byte[]> loadExtensions(DataInputStream dis) throws IOException {
		Map<String, byte[]> extensions = new HashMap<String, byte[]>();

		int extensionCnt = dis.readInt();

		for (int i = 0; i < extensionCnt; i++) {
			int oidLen = dis.readInt();

			char[] oidChars = new char[oidLen];

			for (int j = 0; j < oidLen; j++) {
				oidChars[j] = dis.readChar();
			}

			String oid = new String(oidChars);

			int valueLen = dis.readInt();
			byte[] value = new byte[valueLen];

			dis.readFully(value);

			extensions.put(oid, value);
		}

		return extensions;
	}

	/**
	 * Load X.509 extension set.
	 *
	 * @param is
	 *            Stream to load from
	 * @return X.509 extension set
	 * @throws X509ExtensionSetLoadException
	 *             If stream contents are not a valid X.509 extension set
	 * @throws IOException
	 *             If an I/O problem occurred
	 */

	/**
	 * Save X.509 extension set.
	 *
	 * @param os
	 *            Stream to save to
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public void save(OutputStream os) throws IOException {
		try (DataOutputStream dos = new DataOutputStream(os)) {

			dos.writeLong(FILE_MAGIC_NUMBER);
			dos.writeInt(FILE_VERSION);

			saveExtensions(criticalExtensions, dos);
			saveExtensions(nonCriticalExtensions, dos);
		}
	}

	private void saveExtensions(Map<String, byte[]> extensions, DataOutputStream dos) throws IOException {
		dos.writeInt(extensions.size());

		for (String oid : extensions.keySet()) {
			dos.writeInt(oid.length());
			dos.writeChars(oid);

			byte[] value = extensions.get(oid);
			dos.writeInt(value.length);
			dos.write(value);
		}
	}
}
