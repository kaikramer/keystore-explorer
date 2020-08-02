/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.kse.crypto.CryptoException;
import org.kse.crypto.publickey.KeyIdentifierGenerator;

/**
 * Helper class for updating a set of extensions (mainly for saving/loading extensions or for transferring extensions
 * from CSR or other certificate)
 *
 */
public class X509ExtensionSetUpdater {

	private X509ExtensionSetUpdater() {
		// hide c-tor
	}

	/**
	 * Update extensions of this set with data from issuer certificate
	 *
	 * @param extensionSet Extensions
	 * @param subjectPublicKey New subject public key
	 * @param issuerPublicKey New issuer public key
	 * @param issuerCertName New issuer DN
	 * @param issuerCertSerialNumber New SN
	 * @throws CryptoException For example when hash value cannot be calculated
	 * @throws IOException If the content cannot be encoded
	 */
	public static void update(X509ExtensionSet extensionSet, PublicKey subjectPublicKey, PublicKey issuerPublicKey,
			X500Name issuerCertName, BigInteger issuerCertSerialNumber) throws CryptoException, IOException {

		Set<String> allExtensions = new HashSet<>(extensionSet.getCriticalExtensionOIDs());
		allExtensions.addAll(extensionSet.getNonCriticalExtensionOIDs());

		for (String extensionOid : allExtensions) {

			switch (X509ExtensionType.resolveOid(extensionOid)) {
			case AUTHORITY_KEY_IDENTIFIER:
				updateAKI(extensionSet, extensionOid, issuerPublicKey, issuerCertName, issuerCertSerialNumber);
				break;
			case SUBJECT_KEY_IDENTIFIER:
				updateSKI(extensionSet, extensionOid, subjectPublicKey);
				break;
			default:
				break;
			}
		}
	}


	private static void updateSKI(X509ExtensionSet extensionSet, String extensionOid, PublicKey subjectPublicKey)
			throws CryptoException, IOException {

		// extracting old SKI data not necessary because there is only one possible component in SKI extension

		KeyIdentifierGenerator skiGenerator = new KeyIdentifierGenerator(subjectPublicKey);
		SubjectKeyIdentifier ski = new SubjectKeyIdentifier(skiGenerator.generate160BitHashId());
		byte[] skiEncoded = X509Ext.wrapInOctetString(ski.getEncoded(ASN1Encoding.DER));

		// update
		extensionSet.addExtension(extensionOid, extensionSet.isCritical(extensionOid), skiEncoded);
	}


	private static void updateAKI(X509ExtensionSet extensionSet, String extensionOid, PublicKey newIssuerPublicKey,
			X500Name newIssuerCertName, BigInteger newIssuerSerialNumber) throws CryptoException, IOException {

		// extract old AKI data
		byte[] extensionValue = X509Ext.unwrapExtension(extensionSet.getExtensionValue(extensionOid));
		AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(extensionValue);
		byte[] keyIdentifier = authorityKeyIdentifier.getKeyIdentifier();
		BigInteger authorityCertSerialNumber = authorityKeyIdentifier.getAuthorityCertSerialNumber();

		// generate new values
		byte[] newKeyIdentifier = new KeyIdentifierGenerator(newIssuerPublicKey).generate160BitHashId();
		GeneralNames newCertIssuer = new GeneralNames(new GeneralName[] { new GeneralName(newIssuerCertName) });

		// create new AKI object with same components as before
		if ((keyIdentifier != null) && (authorityCertSerialNumber == null)) {
			authorityKeyIdentifier = new AuthorityKeyIdentifier(newKeyIdentifier);
		} else if (keyIdentifier == null) {
			authorityKeyIdentifier = new AuthorityKeyIdentifier(newCertIssuer, newIssuerSerialNumber);
		} else {
			authorityKeyIdentifier = new AuthorityKeyIdentifier(newKeyIdentifier, newCertIssuer, newIssuerSerialNumber);
		}

		// encode extension value
		byte[] encodedValue = X509Ext.wrapInOctetString(authorityKeyIdentifier.getEncoded(ASN1Encoding.DER));

		// update
		extensionSet.addExtension(extensionOid, extensionSet.isCritical(extensionOid), encodedValue);
	}
}
