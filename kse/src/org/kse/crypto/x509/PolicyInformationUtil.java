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

import static org.kse.crypto.x509.CertificatePolicyQualifierType.PKIX_CPS_POINTER_QUALIFIER;
import static org.kse.crypto.x509.CertificatePolicyQualifierType.PKIX_USER_NOTICE_QUALIFIER;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.NoticeReference;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;

/**
 * Policy Information utility methods.
 *
 */
public class PolicyInformationUtil {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");

	// @formatter:off

	/*
	 * PolicyInformation ::= ASN1Sequence { policyIdentifier CertPolicyId,
	 * policyQualifiers ASN1Sequence SIZE (1..MAX) OF PolicyQualifierInfo
	 * OPTIONAL }
	 *
	 * CertPolicyId ::= OBJECT IDENTIFIER
	 *
	 * PolicyQualifierInfo ::= ASN1Sequence { policyQualifierId
	 * PolicyQualifierId, qualifier ANY DEFINED BY policyQualifierId }
	 *
	 * -- policyQualifierIds for Internet policy qualifiers
	 *
	 * id-qt OBJECT IDENTIFIER ::= { id-pkix 2 } id-qt-cps OBJECT IDENTIFIER ::=
	 * { id-qt 1 } id-qt-unotice OBJECT IDENTIFIER ::= { id-qt 2 }
	 *
	 * PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
	 *
	 * Qualifier ::= CHOICE { cPSuri CPSuri, userNotice UserNotice }
	 *
	 * CPSuri ::= DERIA5String
	 *
	 * UserNotice ::= ASN1Sequence { noticeRef NoticeReference OPTIONAL,
	 * explicitText DisplayText OPTIONAL}
	 *
	 * NoticeReference ::= ASN1Sequence { organization DisplayText,
	 * noticeNumbers ASN1Sequence OF ASN1Integer }
	 *
	 * DisplayText ::= CHOICE { ia5String DERIA5String (SIZE (1..200)),
	 * visibleString VisibleString (SIZE (1..200)), bmpString BMPString (SIZE
	 * (1..200)), utf8String UTF8String (SIZE (1..200)) }
	 */

	// @formatter:on

	/**
	 * Get string representation of policy information.
	 *
	 * @param policyInformation
	 *            Policy information
	 * @return String representation of policy information
	 * @throws IOException
	 *             If policy information is invalid
	 */
	public static String toString(PolicyInformation policyInformation) throws IOException {
		StringBuffer sbPolicyInformation = new StringBuffer();

		ASN1ObjectIdentifier policyIdentifier = policyInformation.getPolicyIdentifier();

		sbPolicyInformation.append(MessageFormat.format(res.getString("PolicyInformationUtil.PolicyIdentifier"),
				policyIdentifier.getId()));

		ASN1Sequence policyQualifiers = policyInformation.getPolicyQualifiers();

		if (policyQualifiers != null) {
			sbPolicyInformation.append(", ");

			StringBuffer sbPolicyQualifiers = new StringBuffer();

			for (int i = 0; i < policyQualifiers.size(); i++) {
				PolicyQualifierInfo policyQualifierInfo =
						PolicyQualifierInfo.getInstance(policyQualifiers.getObjectAt(i));

				sbPolicyQualifiers.append(toString(policyQualifierInfo));

				if ((i + 1) < policyQualifiers.size()) {
					sbPolicyQualifiers.append(", ");
				}
			}

			sbPolicyInformation.append(MessageFormat.format(res.getString("PolicyInformationUtil.PolicyQualifiers"),
					sbPolicyQualifiers));
		}

		return sbPolicyInformation.toString();
	}

	/**
	 * Get string representation of policy qualifier info.
	 *
	 * @param policyQualifierInfo
	 *            Policy qualifier info
	 * @return String representation of policy qualifier info
	 * @throws IOException
	 *             If policy qualifier info is invalid
	 */
	public static String toString(PolicyQualifierInfo policyQualifierInfo) throws IOException {
		StringBuffer sbPolicyQualifier = new StringBuffer();

		ASN1ObjectIdentifier policyQualifierId = policyQualifierInfo.getPolicyQualifierId();

		CertificatePolicyQualifierType certificatePolicyQualifierType = CertificatePolicyQualifierType
				.resolveOid(policyQualifierId.getId());

		if (certificatePolicyQualifierType == PKIX_CPS_POINTER_QUALIFIER) {
			DERIA5String cpsPointer = ((DERIA5String) policyQualifierInfo.getQualifier());

			sbPolicyQualifier
			.append(MessageFormat.format(res.getString("PolicyInformationUtil.CpsPointer"), cpsPointer));
		} else if (certificatePolicyQualifierType == PKIX_USER_NOTICE_QUALIFIER) {
			ASN1Encodable userNoticeObj = policyQualifierInfo.getQualifier();

			UserNotice userNotice = UserNotice.getInstance(userNoticeObj);

			sbPolicyQualifier.append(MessageFormat.format(res.getString("PolicyInformationUtil.UserNotice"),
					toString(userNotice)));
		}

		return sbPolicyQualifier.toString();
	}

	/**
	 * Get string representation of user notice.
	 *
	 * @param userNotice
	 *            User notice
	 * @return String representation of user notice
	 */
	public static String toString(UserNotice userNotice) {
		StringBuffer sbUserNotice = new StringBuffer();

		NoticeReference noticeReference = userNotice.getNoticeRef();

		if (noticeReference != null) {
			DisplayText organization = noticeReference.getOrganization();

			if (organization != null) {
				sbUserNotice.append(MessageFormat.format(res.getString("PolicyInformationUtil.Organization"),
						organization.getString()));

				if ((noticeReference.getNoticeNumbers() != null) || (userNotice.getExplicitText() != null)) {
					sbUserNotice.append(", ");
				}
			}

			ASN1Integer[] noticeNumbers = noticeReference.getNoticeNumbers();

			StringBuffer sbNoticeNumbers = new StringBuffer();

			if (noticeNumbers != null) {
				for (int i = 0; i < noticeNumbers.length; i++) {
					ASN1Integer noticeNumber = noticeNumbers[i];

					sbNoticeNumbers.append(noticeNumber.getValue().intValue());

					if ((i + 1) < noticeNumbers.length) {
						sbNoticeNumbers.append(" ");
					}
				}

				sbUserNotice.append(MessageFormat.format(res.getString("PolicyInformationUtil.NoticeNumbers"),
						sbNoticeNumbers.toString()));

				if (userNotice.getExplicitText() != null) {
					sbUserNotice.append(", ");
				}
			}
		}

		DisplayText explicitText = userNotice.getExplicitText();

		if (explicitText != null) {
			sbUserNotice.append(MessageFormat.format(res.getString("PolicyInformationUtil.ExplicitText"),
					explicitText.getString()));
		}

		return sbUserNotice.toString();
	}
}
