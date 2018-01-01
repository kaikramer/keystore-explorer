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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * PolicyConstraints from RFC 5280
 *
 * <pre>
 * PolicyConstraints ::= SEQUENCE {
 *     requireExplicitPolicy           [0] SkipCerts OPTIONAL,
 *     inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
 *
 * SkipCerts ::= INTEGER (0..MAX)
 * </pre>
 *
 */
public class PolicyConstraints extends ASN1Object {

	int requireExplicitPolicy = -1;
	int inhibitPolicyMapping = -1;

	public static PolicyConstraints getInstance(Object obj){
		if(obj instanceof PolicyConstraints){
			return (PolicyConstraints)obj;
		}
		if(obj instanceof ASN1Sequence){
			return new PolicyConstraints((ASN1Sequence)obj);
		}
		if (obj instanceof byte[]) {
			return new PolicyConstraints(ASN1Sequence.getInstance(obj));
		}
		throw new IllegalArgumentException("invalid sequence");
	}

	private PolicyConstraints(ASN1Sequence seq) {
		if (seq.size() > 2) {
			throw new IllegalArgumentException("sequence length > 2");
		}

		for (int i = 0; i < seq.size(); i++) {
			ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
			switch (taggedObj.getTagNo()) {
			case 0:
				requireExplicitPolicy = ASN1Integer.getInstance(taggedObj.getObject()).getValue().intValue();
				break;
			case 1:
				inhibitPolicyMapping = ASN1Integer.getInstance(taggedObj.getObject()).getValue().intValue();
				break;
			default:
				throw new IllegalArgumentException("wrong tag number");
			}
		}
	}

	/**
	 * Creates a new PolicyConstraints object with the given
	 * requireExplicitPolicy and inhibitPolicyMapping.
	 */
	public PolicyConstraints(int requireExplicitPolicy, int inhibitPolicyMapping) {
		this.requireExplicitPolicy = requireExplicitPolicy;
		this.inhibitPolicyMapping = inhibitPolicyMapping;
	}

	public int getRequireExplicitPolicy() {
		return requireExplicitPolicy;
	}

	public int getInhibitPolicyMapping() {
		return inhibitPolicyMapping;
	}


	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();

		if (requireExplicitPolicy != -1) {
			vec.add(new DERTaggedObject(0, new ASN1Integer(requireExplicitPolicy)));
		}

		if (inhibitPolicyMapping != -1) {
			vec.add(new DERTaggedObject(1, new ASN1Integer(inhibitPolicyMapping)));
		}

		return new DERSequence(vec);
	}
}
