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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.DistributionPoint;

/**
 * X509 extension CRLDistributionPoints, RFC 5280
 *
 * <pre>
 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 * </pre>
 *
 */
public class CRLDistributionPoints extends ASN1Object {

	List<DistributionPoint> distributionPointList;

	/**
	 * Create an new CRLDistributionPoints object from given distribution
	 * points.
	 */
	public CRLDistributionPoints(List<DistributionPoint> distributionPointList) {
		this.distributionPointList = distributionPointList;
	}

	public static CRLDistributionPoints getInstance(Object obj) {
		if (obj instanceof CRLDistributionPoints) {
			return (CRLDistributionPoints) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new CRLDistributionPoints((ASN1Sequence) obj);
		} else if (obj instanceof byte[]) {
			return new CRLDistributionPoints(ASN1Sequence.getInstance(obj));
		}

		throw new IllegalArgumentException("unknown object type");
	}

	private CRLDistributionPoints(ASN1Sequence seq) {
		distributionPointList = new ArrayList<DistributionPoint>();
		for (int i = 0; i != seq.size(); i++) {
			distributionPointList.add(DistributionPoint.getInstance(seq.getObjectAt(i)));
		}
	}

	/**
	 * Returns the distribution points making up the sequence.
	 */
	public List<DistributionPoint> getDistributionPointList() {
		return distributionPointList;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		Iterator<DistributionPoint> it = distributionPointList.iterator();
		while (it.hasNext()) {
			v.add(it.next().toASN1Primitive());
		}
		return new DERSequence(v);
	}
}