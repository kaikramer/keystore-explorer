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

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;

/**
 * X509 extension SubjectInfoAccess, RFC5280:
 *
 * SubjectInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
 *
 * AccessDescription ::= SEQUENCE {
 * 		accessMethod OBJECT IDENTIFIER,
 * 		accessLocation GeneralName }
 *
 */
public class SubjectInfoAccess extends ASN1Object {

	private List<AccessDescription> accessDescriptions;

	/**
	 * Creates a new instance with the given list of accessDescription.
	 */
	public SubjectInfoAccess(List<AccessDescription> accessDescriptions) {
		this.accessDescriptions = accessDescriptions;
	}

	public static SubjectInfoAccess getInstance(Object obj) {
		if (obj instanceof SubjectInfoAccess) {
			return (SubjectInfoAccess) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new SubjectInfoAccess((ASN1Sequence) obj);
		} else if (obj instanceof byte[]) {
			return new SubjectInfoAccess(ASN1Sequence.getInstance(obj));
		}

		throw new IllegalArgumentException("unknown object");
	}

	private SubjectInfoAccess(ASN1Sequence seq) {
		accessDescriptions = new Vector<AccessDescription>();

		for (int i = 0; i != seq.size(); i++) {
			accessDescriptions.add(AccessDescription.getInstance(seq.getObjectAt(i)));
		}
	}

	/**
	 * Returns a list with the AccessDescription objects.
	 */
	public List<AccessDescription> getAccessDescriptionList() {
		return accessDescriptions;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();
		Iterator<AccessDescription> it = accessDescriptions.iterator();
		while (it.hasNext()) {
			vec.add(it.next().toASN1Primitive());
		}

		return new DERSequence(vec);
	}
}
