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

import java.util.Arrays;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Helper class that represents single <code>PolicyMapping</code> objects, that are used in KSE
 * because binor had them.
 *
 * RFC 5280 and BC only know <code>PolicyMappings</code> (= sequence of <code>PolicyMapping</code>):
 * <pre>
 * PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 *    issuerDomainPolicy      CertPolicyId,
 *    subjectDomainPolicy     CertPolicyId }
 *
 * CertPolicyId ::= OBJECT IDENTIFIER
 * <pre>
 *
 */
public class PolicyMapping extends ASN1Object {

	private ASN1ObjectIdentifier issuerDomainPolicy;
	private ASN1ObjectIdentifier subjectDomainPolicy;

	/**
	 * Constructor
	 *
	 * @param issuerDomainPolicy
	 * @param subjectDomainPolicy
	 */
	public PolicyMapping(ASN1ObjectIdentifier issuerDomainPolicy, ASN1ObjectIdentifier subjectDomainPolicy) {

		if (subjectDomainPolicy == null) {
			throw new NullPointerException("subjectDomainPolicy must not be null.");
		}

		if (issuerDomainPolicy == null) {
			throw new NullPointerException("issuerDomainPolicy must not be null.");
		}

		this.issuerDomainPolicy = issuerDomainPolicy;
		this.subjectDomainPolicy = subjectDomainPolicy;
	}

	/**
	 * Returns issuerDomainPolicy.
	 * @return issuerDomainPolicy
	 */
	public ASN1ObjectIdentifier getIssuerDomainPolicy() {
		return this.issuerDomainPolicy;
	}

	/**
	 * Returns subjectDomainPolicy.
	 * @return subjectDomainPolicy
	 */
	public ASN1ObjectIdentifier getSubjectDomainPolicy() {
		return this.subjectDomainPolicy;
	}

	/**
	 * Creates a new <code>PolicyMapping</code> instance.
	 */
	public static PolicyMapping getInstance(Object obj) {

		if (obj instanceof PolicyMapping) {
			return (PolicyMapping) obj;
		}
		if (obj != null) {
			return new PolicyMapping(ASN1Sequence.getInstance(obj));
		}

		return null;
	}

	private PolicyMapping(ASN1Sequence seq) {
		// java object in sequence is actually not ASN1ObjectIdentifier but CertPolicyId,
		// so we do a conversion in order to avoid possible class cast exception here
		this.issuerDomainPolicy = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0).toASN1Primitive());
		this.subjectDomainPolicy = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1).toASN1Primitive());
	}

	@Override
	public boolean equals(Object paramObject) {

		if (paramObject == null) {
			return false;
		}

		try {
			return Arrays.equals(((ASN1Object) paramObject).getEncoded(), getEncoded());
		} catch (Exception e) {
			// ignore
		}
		return false;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {

		ASN1EncodableVector dv = new ASN1EncodableVector();
		dv.add(issuerDomainPolicy);
		dv.add(subjectDomainPolicy);
		return new DERSequence(dv);
	}
}
