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
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralSubtree;

/**
 * Implements <code>GeneralSubtrees</code> from RFC 5280:
 * <pre>
 * GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
 * </pre>
 *
 */
public class GeneralSubtrees implements ASN1Encodable {

	private List<GeneralSubtree> subtrees;

	/**
	 * Create <code>GeneralSubtrees</code> from list of <code>GeneralSubtree</code>
	 * objects.
	 *
	 * @param subtrees
	 */
	public GeneralSubtrees(List<GeneralSubtree> subtrees) {
		this.subtrees = subtrees;
	}

	/**
	 * Create <code>GeneralSubtrees</code> from array of <code>GeneralSubtree</code>
	 * objects.
	 *
	 * @param subtrees
	 */
	public GeneralSubtrees(GeneralSubtree[] subtrees) {
		this.subtrees = new ArrayList<GeneralSubtree>(Arrays.asList(subtrees));
	}

	private GeneralSubtrees(ASN1Sequence seq) {
		subtrees = new ArrayList<GeneralSubtree>();
		for (int i = 0; i < seq.size(); i++) {
			subtrees.add(GeneralSubtree.getInstance(seq.getObjectAt(i)));
		}
	}

	public static GeneralSubtrees getInstance(Object obj) {
		if (obj instanceof GeneralSubtrees) {
			return (GeneralSubtrees) obj;
		}
		if (obj instanceof ASN1Sequence) {
			return new GeneralSubtrees((ASN1Sequence) obj);
		}
		throw new IllegalArgumentException("invalid ASN1Sequence");
	}

	public List<GeneralSubtree> getGeneralSubtrees() {
		return subtrees;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();
		for (int i = 0; i < subtrees.size(); i++) {
			vec.add(subtrees.get(i));
		}
		return new DERSequence(vec);
	}

}
