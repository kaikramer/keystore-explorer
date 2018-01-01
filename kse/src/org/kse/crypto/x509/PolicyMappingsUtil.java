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
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.PolicyMappings;

/**
 * Helper class that does some conversions with BC's <code>PolicyMappings</code> objects.
 *
 */
public class PolicyMappingsUtil {

	/**
	 * Creates list of <code>PolicyMapping</code> objects from an <code>PolicyMappings</code> object.
	 *
	 * @param policyMappings
	 * @return List of PolicyMapping
	 */
	public static List<PolicyMapping> getListOfPolicyMappings(PolicyMappings policyMappings) {

		ASN1Sequence policyMappingsSeq = (ASN1Sequence) policyMappings.toASN1Primitive();
		ASN1Encodable[] policyMappingsArray = policyMappingsSeq.toArray();

		List<PolicyMapping> policyMappingsList = new ArrayList<PolicyMapping>();

		for (ASN1Encodable asn1Encodable : policyMappingsArray) {
			policyMappingsList.add(PolicyMapping.getInstance(asn1Encodable));
		}

		return policyMappingsList;
	}

	/**
	 * Creates <code>PolicyMappings</code> objects from list of <code>PolicyMapping</code>
	 *
	 * @param listOfPolicyMappings
	 * @return <code>PolicyMappings</code> object
	 */
	public static PolicyMappings createFromList(List<PolicyMapping> listOfPolicyMappings) {

		CertPolicyId[] issuerDomainPolicies = new CertPolicyId[listOfPolicyMappings.size()];
		CertPolicyId[] subjectDomainPolicies = new CertPolicyId[listOfPolicyMappings.size()];

		for (int i = 0; i < listOfPolicyMappings.size(); i++) {
			PolicyMapping policyMapping = listOfPolicyMappings.get(i);

			issuerDomainPolicies[i] = CertPolicyId.getInstance(policyMapping.getIssuerDomainPolicy());
			subjectDomainPolicies[i] = CertPolicyId.getInstance(policyMapping.getSubjectDomainPolicy());
		}

		return new PolicyMappings(issuerDomainPolicies, subjectDomainPolicies);
	}

	/**
	 * Add <code>PolicyMapping</code> to a <code>PolicyMappings</code> object
	 *
	 * @param policyMapping The policy mapping to be added.
	 * @param policyMappings The policy mappings to add to.
	 * @return New <code>PolicyMappings</code> object with additional policyMapping
	 */
	public static PolicyMappings add(PolicyMapping policyMapping, PolicyMappings policyMappings) {
		List<PolicyMapping> policyMappingsList = PolicyMappingsUtil.getListOfPolicyMappings(policyMappings);
		policyMappingsList.add(policyMapping);

		policyMappings = PolicyMappingsUtil.createFromList(policyMappingsList);

		return policyMappings;
	}

	/**
	 * Removes a <code>PolicyMapping</code> from a <code>PolicyMappings</code> object
	 *
	 * @param policyMapping The policy mapping to be removed.
	 * @param policyMappings The policy mappings to remove from.
	 * @return New <code>PolicyMappings</code> object without policyMapping
	 */
	public static PolicyMappings remove(PolicyMapping policyMapping, PolicyMappings policyMappings) {
		List<PolicyMapping> policyMappingsList = PolicyMappingsUtil.getListOfPolicyMappings(policyMappings);
		policyMappingsList.remove(policyMapping);

		policyMappings = PolicyMappingsUtil.createFromList(policyMappingsList);

		return policyMappings;
	}
}
