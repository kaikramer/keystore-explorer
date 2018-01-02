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
import java.math.BigInteger;
import java.text.MessageFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.DeclarationOfMajority;
import org.bouncycastle.asn1.isismtt.x509.MonetaryLimit;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.isismtt.x509.ProcurationSyntax;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.NoticeReference;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.kse.utilities.StringUtils;
import org.kse.utilities.io.HexUtil;
import org.kse.utilities.io.IndentChar;
import org.kse.utilities.io.IndentSequence;
import org.kse.utilities.oid.ObjectIdUtil;

/**
 * Holds the information of an X.509 extension and provides the ability to get
 * the extension's name and value as a string.
 */
public class X509Ext {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");

	private String name;
	private ASN1ObjectIdentifier oid;
	private byte[] value;
	private boolean critical;

	public static final IndentSequence INDENT = new IndentSequence(IndentChar.SPACE, 4);
	public static final String NEWLINE = "\n";

	/**
	 * Construct a new immutable X509Ext.
	 *
	 * @param oid      X509Extension object identifier
	 * @param value    X509Extension value as a DER-encoded OCTET string
	 * @param critical Critical extension?
	 */
	public X509Ext(ASN1ObjectIdentifier oid, byte[] value, boolean critical) {
		this.oid = oid;

		this.value = new byte[value.length];
		System.arraycopy(value, 0, this.value, 0, this.value.length);

		this.critical = critical;

		name = lookupFriendlyName();
	}

	/**
	 * Construct a new immutable X509Ext.
	 *
	 * @param oid      X509Extension object identifier
	 * @param value    X509Extension value as a DER-encoded OCTET string
	 * @param critical Critical extension?
	 */
	public X509Ext(String oid, byte[] value, boolean critical) {
		this(new ASN1ObjectIdentifier(oid), value, critical);
	}

	/**
	 * Get extension object identifier.
	 *
	 * @return X509Extension object identifier
	 */
	public ASN1ObjectIdentifier getOid() {
		return oid;
	}

	/**
	 * Get extension value as a DER-encoded OCTET string.
	 *
	 * @return X509Extension value
	 */
	public byte[] getValue() {
		byte[] value = new byte[this.value.length];
		System.arraycopy(this.value, 0, value, 0, this.value.length);
		return value;
	}

	/**
	 * Is extension critical?
	 *
	 * @return True if is, false otherwise
	 */
	public boolean isCriticalExtension() {
		return critical;
	}

	/**
	 * Get extension name.
	 *
	 * @return X509Extension name or null if unknown
	 */
	public String getName() {
		if (name == null) {
			return null;
		}

		return name;
	}

	/**
	 * Get extension value as a string.
	 *
	 * @return X509Extension value as a string
	 * @throws IOException If an ASN.1 coding problem occurs
	 * @throws IOException If an I/O problem occurs
	 */
	public String getStringValue() throws IOException {

		// Convert value from DER encoded octet string value to binary DER encoding
		ASN1OctetString octetString = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(value));
		byte[] octets = octetString.getOctets();

		X509ExtensionType type = X509ExtensionType.resolveOid(oid.getId());

		// handle unknown OID
		if (type == null) {
			return HexUtil.getHexClearDump(octets);
		}

		switch (type) {
		case ENTRUST_VERSION_INFORMATION:
			return getEntrustVersionInformationStringValue(octets);
		case AUTHORITY_INFORMATION_ACCESS:
			return getAuthorityInformationAccessStringValue(octets);
		case SUBJECT_INFORMATION_ACCESS:
			return getSubjectInformationAccessStringValue(octets);
		case SUBJECT_DIRECTORY_ATTRIBUTES:
			return getSubjectDirectoryAttributesStringValue(octets);
		case SUBJECT_KEY_IDENTIFIER:
			return getSubjectKeyIndentifierStringValue(octets);
		case KEY_USAGE:
			return getKeyUsageStringValue(octets);
		case PRIVATE_KEY_USAGE_PERIOD:
			return getPrivateKeyUsagePeriodStringValue(octets);
		case SUBJECT_ALTERNATIVE_NAME:
			return getSubjectAlternativeNameStringValue(octets);
		case ISSUER_ALTERNATIVE_NAME:
			return getIssuerAlternativeNameStringValue(octets);
		case BASIC_CONSTRAINTS:
			return getBasicConstraintsStringValue(octets);
		case CRL_NUMBER:
			return getCrlNumberStringValue(octets);
		case REASON_CODE:
			return getReasonCodeStringValue(octets);
		case HOLD_INSTRUCTION_CODE:
			return getHoldInstructionCodeStringValue(octets);
		case INVALIDITY_DATE:
			return getInvalidityDateStringValue(octets);
		case DELTA_CRL_INDICATOR:
			return getDeltaCrlIndicatorStringValue(octets);
		case ISSUING_DISTRIBUTION_POINT:
			return getIssuingDistributionPointStringValue(octets);
		case CERTIFICATE_ISSUER:
			return getCertificateIssuerStringValue(octets);
		case NAME_CONSTRAINTS:
			return getNameConstraintsStringValue(octets);
		case CRL_DISTRIBUTION_POINTS:
			return getCrlDistributionPointsStringValue(octets);
		case CERTIFICATE_POLICIES:
			return getCertificatePoliciesStringValue(octets);
		case POLICY_MAPPINGS:
			return getPolicyMappingsStringValue(octets);
		case AUTHORITY_KEY_IDENTIFIER:
			return getAuthorityKeyIdentifierStringValue(octets);
		case POLICY_CONSTRAINTS:
			return getPolicyConstraintsStringValue(octets);
		case EXTENDED_KEY_USAGE:
			return getExtendedKeyUsageStringValue(octets);
		case FRESHEST_CRL:
			return getFreshestCrlStringValue(octets);
		case INHIBIT_ANY_POLICY:
			return getInhibitAnyPolicyStringValue(octets);
		case NETSCAPE_CERTIFICATE_TYPE:
			return getNetscapeCertificateTypeStringValue(octets);
		case NETSCAPE_BASE_URL:
			return getNetscapeBaseUrlStringValue(octets);
		case NETSCAPE_REVOCATION_URL:
			return getNetscapeRevocationUrlStringValue(octets);
		case NETSCAPE_CA_REVOCATION_URL:
			return getNetscapeCaRevocationUrlStringValue(octets);
		case NETSCAPE_CERTIFICATE_RENEWAL_URL:
			return getNetscapeCertificateRenewalStringValue(octets);
		case NETSCAPE_CA_POLICY_URL:
			return getNetscapeCaPolicyUrlStringValue(octets);
		case NETSCAPE_SSL_SERVER_NAME:
			return getNetscapeSslServerNameStringValue(octets);
		case NETSCAPE_COMMENT:
			return getNetscapeCommentStringValue(octets);
		case BIOMETRIC_INFO:
			return getBiometricInfoStringValue(octets);
		case QC_STATEMENTS:
			return getQcStatementsStringValue(octets);
		case OCSP_NO_CHECK:
			return getOcspNoCheckStringValue(octets);
		case LIABILITY_LIMITATION_FLAG:
			return getLiabilityLimitationFlagStringValue(octets);
		case DATE_OF_CERT_GEN:
			return getDateOfCertGenStringValue(octets);
		case PROCURATION:
			return getProcurationStringValue(octets);
		case ADMISSION:
			return getAdmissionStringValue(octets);
		case MONETARY_LIMIT:
			return getMonetaryLimitStringValue(octets);
		case DECLARATION_OF_MAJORITY:
			return getDeclarationOfMajorityStringValue(octets);
		case ICCSN:
			return getICCSNStringValue(octets);
		case RESTRICTION:
			return getRestrictionStringValue(octets);
		case ADDITIONAL_INFORMATION:
			return getAdditionalInformationStringValue(octets);
		case VALIDITY_MODEL:
			return getValidityModelStringValue(octets);
		case MS_ENROLL_CERT_TYPE_EXTENSION:
			return getMsCertTypeStringValue(octets);
		case MS_CA_VERSION:
			return  getMsCaVersionStringValue(octets);
		case MS_CRL_NEXT_PUBLISH:
			return  getMsCrlNextPublishStringValue(octets);
		case MS_CERTIFICATE_TEMPLATE:
			return getMsCertificateTemplateStringValue(octets);
		case MS_APPLICATION_POLICIES:
			return HexUtil.getHexClearDump(octets);
		case SMIME_CAPABILITIES:
			return getSMIMECapabilitiesStringValue(octets);
		case VS_CZAG:
		case VS_FIDELITY_TOKEN:
		case VS_IN_BOX_V1:
		case VS_IN_BOX_V2:
		case VS_SERIAL_NUMBER_ROLLOVER:
		case VS_ON_SITE_JURISDICTION_HASH:
			// most VeriSign extensions contain just an IA5STRING
			return DERIA5String.getInstance(octets).getString();
		case VS_TOKEN_TYPE:
		case VS_UNKNOWN:
			return getBitString(octets);
		case VS_NON_VERIFIED:
			return getVeriSignNonVerified(octets);
		default:
			// X509Extension not recognized or means to output it not defined - just dump out hex and clear text
			return HexUtil.getHexClearDump(octets);
		}
	}

	private String lookupFriendlyName() {
		X509ExtensionType type = X509ExtensionType.resolveOid(oid.getId());

		if (type != null) {
			return type.friendly();
		}

		return null;
	}

	private String getEntrustVersionInformationStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * EntrustVersInfoSyntax ::= OCTET STRING
		 *
		 * entrustVersInfo EXTENSION ::= { SYNTAX EntrustVersInfoSyntax,
		 * IDENTIFIED BY {id-entrust 0} }
		 *
		 * EntrustVersInfoSyntax ::= ASN1Sequence { entrustVers GeneralString,
		 * entrustInfoFlags EntrustInfoFlags }
		 *
		 * EntrustInfoFlags ::= BIT STRING { keyUpdateAllowed newExtensions (1),
		 * pKIXCertificate (2) }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		ASN1Sequence entrustVersInfo = (ASN1Sequence) ASN1Primitive.fromByteArray(value);

		DERGeneralString entrustVers = (DERGeneralString) entrustVersInfo.getObjectAt(0);
		DERBitString entrustInfoFlags = (DERBitString) entrustVersInfo.getObjectAt(1);

		sb.append(MessageFormat.format(res.getString("EntrustVersion"), entrustVers.getString()));
		sb.append(NEWLINE);
		sb.append(MessageFormat.format(res.getString("EntrustInformationFlags"), entrustInfoFlags.getString()));
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getAuthorityInformationAccessStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * AuthorityInfoAccessSyntax ::= ASN1Sequence SIZE (1..MAX) OF
		 * AccessDescription
		 *
		 * AccessDescription ::= ASN1Sequence { accessMethod OBJECT IDENTIFIER,
		 * accessLocation GeneralName }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		AuthorityInformationAccess authorityInfoAccess = AuthorityInformationAccess.getInstance(value);

		int accessDesc = 0;

		for (AccessDescription accessDescription : authorityInfoAccess.getAccessDescriptions()) {
			accessDesc++;

			// Convert OID to access method
			ASN1ObjectIdentifier accessMethod = accessDescription.getAccessMethod();

			AccessMethodType accessMethodType = AccessMethodType.resolveOid(accessMethod.getId());

			String accessMethodStr = null;

			if (accessMethodType != null) {
				accessMethodStr = accessMethodType.friendly();
			} else {
				// Unrecognised Access Method OID
				accessMethodStr = ObjectIdUtil.toString(accessMethod);
			}

			GeneralName accessLocation = accessDescription.getAccessLocation();

			String accessLocationStr = GeneralNameUtil.toString(accessLocation);

			sb.append(MessageFormat.format(res.getString("AuthorityInformationAccess"), accessDesc));
			sb.append(NEWLINE);
			sb.append(INDENT);
			sb.append(MessageFormat.format(res.getString("AccessMethod"), accessMethodStr));
			sb.append(NEWLINE);
			sb.append(INDENT);
			sb.append(res.getString("AccessLocation"));
			sb.append(NEWLINE);
			sb.append(INDENT.toString(2));
			sb.append(accessLocationStr);
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getSubjectInformationAccessStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * SubjectInfoAccessSyntax ::= ASN1Sequence SIZE (1..MAX) OF
		 * AccessDescription
		 *
		 * AccessDescription ::= ASN1Sequence { accessMethod OBJECT IDENTIFIER,
		 * accessLocation GeneralName }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		SubjectInfoAccess subjectInfoAccess = SubjectInfoAccess.getInstance(value);

		int accessDesc = 0;

		for (AccessDescription accessDescription : subjectInfoAccess.getAccessDescriptionList()) {
			accessDesc++;

			// Convert OID to access method
			ASN1ObjectIdentifier accessMethod = accessDescription.getAccessMethod();

			AccessMethodType accessMethodType = AccessMethodType.resolveOid(accessMethod.getId());

			String accessMethodStr = null;

			if (accessMethodType != null) {
				accessMethodStr = accessMethodType.friendly();
			}
			// Unrecognised Access Method OID
			else {
				accessMethodStr = ObjectIdUtil.toString(accessMethod);
			}

			GeneralName accessLocation = accessDescription.getAccessLocation();

			String accessLocationStr = GeneralNameUtil.toString(accessLocation);

			sb.append(MessageFormat.format(res.getString("SubjectInformationAccess"), accessDesc));
			sb.append(NEWLINE);
			sb.append(INDENT);
			sb.append(MessageFormat.format(res.getString("AccessMethod"), accessMethodStr));
			sb.append(NEWLINE);
			sb.append(INDENT);
			sb.append(res.getString("AccessLocation"));
			sb.append(NEWLINE);
			sb.append(INDENT);
			sb.append(INDENT);
			sb.append(accessLocationStr);
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getSubjectDirectoryAttributesStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * SubjectDirectoryAttributes ::= ASN1Sequence SIZE (1..MAX) OF Attribute
		 *
		 * Attribute ::= ASN1Sequence
		 * {
		 *      type AttributeType,
		 *      values SET OF AttributeValue
		 * }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(value);

		for (Object attribute : subjectDirectoryAttributes.getAttributes()) {

			ASN1ObjectIdentifier attributeType = ((Attribute) attribute).getAttrType();
			String attributeTypeStr = attributeType.getId();

			ASN1Encodable[] attributeValues = ((Attribute) attribute).getAttributeValues();

			for (ASN1Encodable attributeValue : attributeValues) {

				String attributeValueStr = getAttributeValueString(attributeType, attributeValue);

				sb.append(MessageFormat.format("{0}={1}", attributeTypeStr, attributeValueStr));
				sb.append(NEWLINE);
			}
		}

		return sb.toString();
	}

	private String getSubjectKeyIndentifierStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * SubjectKeyIdentifier ::= KeyIdentifier
		 *
		 * KeyIdentifier ::= OCTET STRING
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(value);

		// Get key identifier from octet string
		byte[] keyIdentifierBytes = subjectKeyIdentifier.getKeyIdentifier();

		sb.append(MessageFormat.format(res.getString("SubjectKeyIdentifier"),
				HexUtil.getHexString(keyIdentifierBytes)));
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getKeyUsageStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * KeyUsage ::= BIT STRING { digitalSignature (0), nonRepudiation (1),
		 * keyEncipherment (2), dataEncipherment (3), keyAgreement (4),
		 * keyCertSign (5), cRLSign (6), encipherOnly (7), decipherOnly (8) }
		 */

		// @formatter:on

		DERBitString keyUsage = DERBitString.getInstance(ASN1Primitive.fromByteArray(value));

		int keyUsages = keyUsage.intValue();

		StringBuilder sb = new StringBuilder();

		if (hasKeyUsage(keyUsages, KeyUsage.digitalSignature)) {
			sb.append(res.getString("DigitalSignatureKeyUsage"));
			sb.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.nonRepudiation)) {
			sb.append(res.getString("NonRepudiationKeyUsage"));
			sb.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.keyEncipherment)) {
			sb.append(res.getString("KeyEnciphermentKeyUsage"));
			sb.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.dataEncipherment)) {
			sb.append(res.getString("DataEnciphermentKeyUsage"));
			sb.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.keyAgreement)) {
			sb.append(res.getString("KeyAgreementKeyUsage"));
			sb.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.keyCertSign)) {
			sb.append(res.getString("KeyCertSignKeyUsage"));
			sb.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.cRLSign)) {
			sb.append(res.getString("CrlSignKeyUsage"));
			sb.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.encipherOnly)) {
			sb.append(res.getString("EncipherOnlyKeyUsage"));
			sb.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.decipherOnly)) {
			sb.append(res.getString("DecipherOnlyKeyUsage"));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private boolean hasKeyUsage(int keyUsages, int keyUsage) {
		return (keyUsages & keyUsage) == keyUsage;
	}

	private String getPrivateKeyUsagePeriodStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * PrivateKeyUsagePeriod ::= ASN1Sequence { notBefore [0]
		 * ASN1GeneralizedTime OPTIONAL, notAfter [1] ASN1GeneralizedTime OPTIONAL }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		PrivateKeyUsagePeriod privateKeyUsagePeriod = PrivateKeyUsagePeriod.getInstance(value);

		ASN1GeneralizedTime notBefore = privateKeyUsagePeriod.getNotBefore();
		ASN1GeneralizedTime notAfter = privateKeyUsagePeriod.getNotAfter();

		if (notBefore != null) {
			sb.append(MessageFormat.format(res.getString("NotBeforePrivateKeyUsagePeriod"),
					getGeneralizedTimeString(notBefore)));
		} else {
			sb.append(MessageFormat.format(res.getString("NotBeforePrivateKeyUsagePeriod"),
					res.getString("NoValue")));
		}
		sb.append(NEWLINE);

		if (notAfter != null) {
			sb.append(MessageFormat.format(res.getString("NotAfterPrivateKeyUsagePeriod"),
					getGeneralizedTimeString(notAfter)));
		} else {
			sb.append(MessageFormat.format(res.getString("NotAfterPrivateKeyUsagePeriod"),
					res.getString("NoValue")));
		}
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getSubjectAlternativeNameStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * SubjectAltName ::= GeneralNames
		 *
		 * GeneralNames ::= ASN1Sequence SIZE (1..MAX) OF GeneralName
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		GeneralNames subjectAltName = GeneralNames.getInstance(value);

		for (GeneralName generalName : subjectAltName.getNames()) {
			sb.append(GeneralNameUtil.toString(generalName));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getIssuerAlternativeNameStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * IssuerAltName ::= GeneralNames
		 *
		 * GeneralNames ::= ASN1Sequence SIZE (1..MAX) OF GeneralName
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		GeneralNames issuerAltName = GeneralNames.getInstance(value);

		for (GeneralName generalName : issuerAltName.getNames()) {
			sb.append(GeneralNameUtil.toString(generalName));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getBasicConstraintsStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * BasicConstraints ::= ASN1Sequence { cA ASN1Boolean DEFAULT FALSE,
		 * pathLenConstraint ASN1Integer (0..MAX) OPTIONAL }
		 */

		// @formatter:on

		/*
		 * Getting the DEFAULT returns a false ASN1Boolean when no value present
		 * which saves the bother of a null check
		 */

		StringBuilder sb = new StringBuilder();

		BasicConstraints basicConstraints = BasicConstraints.getInstance(value);

		boolean ca = basicConstraints.isCA();
		BigInteger pathLenConstraint = basicConstraints.getPathLenConstraint();

		if (ca) {
			sb.append(res.getString("SubjectIsCa"));
			sb.append(NEWLINE);
		} else {
			sb.append(res.getString("SubjectIsNotCa"));
			sb.append(NEWLINE);
		}

		if (pathLenConstraint != null) {
			sb.append(MessageFormat.format(res.getString("PathLengthConstraint"), pathLenConstraint
					.intValue()));
			sb.append(NEWLINE);
		} else {
			sb.append(res.getString("NoPathLengthConstraint"));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getCrlNumberStringValue(byte[] value) throws IOException {
		// @formatter:off
		/* CRLNumber ::= ASN1Integer (0..MAX) */
		// @formatter:on

		StringBuilder sb = new StringBuilder();

		CRLNumber crlNumber = CRLNumber.getInstance(value);

		sb.append(HexUtil.getHexString(crlNumber.getCRLNumber()));
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getReasonCodeStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * ReasonCode ::= { CRLReason }
		 *
		 * CRLReason ::= ASN1Enumerated { unspecified (0), keyCompromise (1),
		 * cACompromise (2), affiliationChanged (3), superseded (4),
		 * cessationOfOperation (5), certificateHold (6), removeFromCRL (8),
		 * privilegeWithdrawn (9), aACompromise (10) }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		CRLReason crlReason = CRLReason.getInstance(value);

		long crlReasonLong = crlReason.getValue().longValue();

		if (crlReasonLong == CRLReason.unspecified) {
			sb.append(res.getString("UnspecifiedCrlReason"));
		} else if (crlReasonLong == CRLReason.keyCompromise) {
			sb.append(res.getString("KeyCompromiseCrlReason"));
		} else if (crlReasonLong == CRLReason.cACompromise) {
			sb.append(res.getString("CaCompromiseCrlReason"));
		} else if (crlReasonLong == CRLReason.affiliationChanged) {
			sb.append(res.getString("AffiliationChangedCrlReason"));
		} else if (crlReasonLong == CRLReason.superseded) {
			sb.append(res.getString("SupersededCrlReason"));
		} else if (crlReasonLong == CRLReason.cessationOfOperation) {
			sb.append(res.getString("CessationOfOperationCrlReason"));
		} else if (crlReasonLong == CRLReason.certificateHold) {
			sb.append(res.getString("CertificateHoldCrlReason"));
		} else if (crlReasonLong == CRLReason.removeFromCRL) {
			sb.append(res.getString("RemoveFromCrlCrlReason"));
		} else if (crlReasonLong == CRLReason.privilegeWithdrawn) {
			sb.append(res.getString("PrivilegeWithdrawnCrlReason"));
		} else
			// CRLReason.aACompromise
		{
			sb.append(res.getString("AaCompromiseCrlReason"));
		}

		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getHoldInstructionCodeStringValue(byte[] value) throws IOException {
		// @formatter:off
		/* HoldInstructionCode ::= OBJECT IDENTIFER */
		// @formatter:on

		StringBuilder sb = new StringBuilder();

		ASN1ObjectIdentifier holdInstructionCode = ASN1ObjectIdentifier.getInstance(value);
		HoldInstructionCodeType holdInstructionCodeType =
				HoldInstructionCodeType.resolveOid(holdInstructionCode.getId());

		if (holdInstructionCodeType != null) {
			sb.append(holdInstructionCodeType.friendly());
		} else {
			// Unrecognised Hold Instruction Code
			sb.append(holdInstructionCode.getId());
		}
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getInvalidityDateStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* InvalidityDate ::= ASN1GeneralizedTime */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		ASN1GeneralizedTime invalidityDate = ASN1GeneralizedTime.getInstance(value);

		sb.append(getGeneralizedTimeString(invalidityDate));
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getDeltaCrlIndicatorStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * deltaCRLIndicator EXTENSION ::= { SYNTAX BaseCRLNumber IDENTIFIED BY
		 * id-ce-deltaCRLIndicator }
		 *
		 * BaseCRLNumber ::= CRLNumber
		 *
		 * CRLNumber ::= ASN1Integer (0..MAX)
		 */

		// @formatter:on

		CRLNumber crlNumber = CRLNumber.getInstance(value);
		BigInteger crlNum = crlNumber.getCRLNumber();

		return HexUtil.getHexString(crlNum) + NEWLINE;
	}

	private String getIssuingDistributionPointStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * IssuingDistributionPoint ::= ASN1Sequence {
		 *     distributionPoint [0] DistributionPointName OPTIONAL,
		 *     onlyContainsUserCerts [1] ASN1Boolean DEFAULT FALSE,
		 *     onlyContainsCACerts [2] ASN1Boolean DEFAULT FALSE,
		 *     onlySomeReasons [3] ReasonFlags OPTIONAL,
		 *     indirectCRL [4] ASN1Boolean DEFAULT FALSE,
		 *     onlyContainsAttributeCerts [5] ASN1Boolean DEFAULT FALSE }
		 */

		// @formatter:on

		/*
		 * Getting any DEFAULTS returns a false ASN1Boolean when no value
		 * present which saves the bother of a null check
		 */

		StringBuilder sb = new StringBuilder();

		IssuingDistributionPoint issuingDistributionPoint = IssuingDistributionPoint.getInstance(value);

		DistributionPointName distributionPointName = issuingDistributionPoint.getDistributionPoint();

		if (distributionPointName != null) { // Optional
			sb.append(getDistributionPointNameString(distributionPointName, ""));
		}

		boolean onlyContainsUserCerts = issuingDistributionPoint.onlyContainsUserCerts();
		sb.append(MessageFormat.format(res.getString("OnlyContainsUserCerts"), onlyContainsUserCerts));
		sb.append(NEWLINE);

		boolean onlyContainsCaCerts = issuingDistributionPoint.onlyContainsCACerts();
		sb.append(MessageFormat.format(res.getString("OnlyContainsCaCerts"), onlyContainsCaCerts));
		sb.append(NEWLINE);

		ReasonFlags onlySomeReasons = issuingDistributionPoint.getOnlySomeReasons();
		if (onlySomeReasons != null) {// Optional
			sb.append(res.getString("OnlySomeReasons"));
			sb.append(NEWLINE);

			String[] reasonFlags = getReasonFlagsStrings(onlySomeReasons);

			for (String reasonFlag : reasonFlags) {
				sb.append(INDENT);
				sb.append(reasonFlag);
				sb.append(NEWLINE);
			}
		}

		boolean indirectCrl = issuingDistributionPoint.isIndirectCRL();
		sb.append(MessageFormat.format(res.getString("IndirectCrl"), indirectCrl));
		sb.append(NEWLINE);

		boolean onlyContainsAttributeCerts = issuingDistributionPoint.onlyContainsAttributeCerts();
		sb.append(MessageFormat.format(res.getString("OnlyContainsAttributeCerts"), onlyContainsAttributeCerts));
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getCertificateIssuerStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * certificateIssuer ::= GeneralNames
		 *
		 * GeneralNames ::= ASN1Sequence SIZE (1..MAX) OF GeneralName
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		GeneralNames certificateIssuer = GeneralNames.getInstance(value);

		for (GeneralName generalName : certificateIssuer.getNames()) {
			sb.append(GeneralNameUtil.toString(generalName));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getNameConstraintsStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * NameConstraints ::= ASN1Sequence { permittedSubtrees [0]
		 * GeneralSubtrees OPTIONAL, excludedSubtrees [1] GeneralSubtrees
		 * OPTIONAL }
		 *
		 * GeneralSubtrees ::= ASN1Sequence SIZE (1..MAX) OF GeneralSubtree
		 *
		 * GeneralSubtree ::= ASN1Sequence { base GeneralName, minimum [0]
		 * BaseDistance DEFAULT nodistance, maximum [1] BaseDistance OPTIONAL }
		 *
		 * BaseDistance ::= ASN1Integer {nodistance(0) } (0..MAX)
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		NameConstraints nameConstraints = NameConstraints.getInstance(value);

		GeneralSubtrees permittedSubtrees = null;
		if (nameConstraints.getPermittedSubtrees() != null &&
				nameConstraints.getPermittedSubtrees().length != 0) {
			permittedSubtrees = new GeneralSubtrees(nameConstraints.getPermittedSubtrees());
		}

		sb.append(res.getString("PermittedSubtrees"));

		if (permittedSubtrees == null) {
			sb.append(" ").append(res.getString("NoValue"));
			sb.append(NEWLINE);
		} else {
			sb.append(NEWLINE);

			int permitted = 0;

			for (GeneralSubtree permittedSubtree : permittedSubtrees.getGeneralSubtrees()) {
				permitted++;

				sb.append(INDENT);
				sb.append(MessageFormat.format(res.getString("PermittedSubtree"), permitted));
				sb.append(NEWLINE);

				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(res.getString("Base"));
				sb.append(NEWLINE);

				GeneralName base = permittedSubtree.getBase();

				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(GeneralNameUtil.toString(base));
				sb.append(NEWLINE);

				BigInteger minimum = permittedSubtree.getMinimum();
				int minimumInt = 0; // Default 'nodistance' value

				if (minimum != null) {
					minimumInt = minimum.intValue();
				}

				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(MessageFormat.format(res.getString("Minimum"), minimumInt));
				sb.append(NEWLINE);

				BigInteger maximum = permittedSubtree.getMaximum();

				if (maximum != null) {
					int maximumInt = maximum.intValue();

					sb.append(INDENT);
					sb.append(INDENT);
					sb.append(MessageFormat.format(res.getString("Maximum"), maximumInt));
					sb.append(NEWLINE);
				}
			}
		}

		GeneralSubtree[] excludedSubtreeArray = nameConstraints.getExcludedSubtrees();

		sb.append(res.getString("ExcludedSubtrees"));

		if (excludedSubtreeArray == null) { // Optional
			sb.append(" ").append(res.getString("NoValue"));
			sb.append(NEWLINE);
		} else {

			GeneralSubtrees excludedSubtrees = new GeneralSubtrees(excludedSubtreeArray);

			sb.append(NEWLINE);

			int excluded = 0;

			for (GeneralSubtree excludedSubtree : excludedSubtrees.getGeneralSubtrees()) {
				excluded++;

				sb.append(INDENT);
				sb.append(MessageFormat.format(res.getString("ExcludedSubtree"), excluded));
				sb.append(NEWLINE);

				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(res.getString("Base"));
				sb.append(NEWLINE);

				GeneralName base = excludedSubtree.getBase();

				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(GeneralNameUtil.toString(base));
				sb.append(NEWLINE);

				BigInteger minimum = excludedSubtree.getMinimum();
				int minimumInt = minimum.intValue();

				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(MessageFormat.format(res.getString("Minimum"), minimumInt));
				sb.append(NEWLINE);

				BigInteger maximum = excludedSubtree.getMaximum();

				if (maximum != null) {
					int maximumInt = maximum.intValue();

					sb.append(INDENT);
					sb.append(INDENT);
					sb.append(MessageFormat.format(res.getString("Maximum"), maximumInt));
					sb.append(NEWLINE);
				}
			}
		}

		return sb.toString();
	}

	private String getCrlDistributionPointsStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * CRLDistPointSyntax ::= ASN1Sequence SIZE (1..MAX) OF
		 * DistributionPoint
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		CRLDistPoint crlDistributionPoints = CRLDistPoint.getInstance(value);

		int distPoint = 0;

		for (DistributionPoint distributionPoint : crlDistributionPoints.getDistributionPoints()) {
			distPoint++;

			sb.append(MessageFormat.format(res.getString("CrlDistributionPoint"), distPoint));
			sb.append(NEWLINE);

			sb.append(getDistributionPointString(distributionPoint, INDENT.toString(1)));
		}

		return sb.toString();
	}

	private String getCertificatePoliciesStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * CertificatePolicies ::= ASN1Sequence SIZE (1..MAX) OF PolicyInformation
		 *
		 * PolicyInformation ::= ASN1Sequence
		 * {
		 *      policyIdentifier CertPolicyId,
		 *      policyQualifiers ASN1Sequence SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
		 * }
		 *
		 * CertPolicyId ::= OBJECT IDENTIFIER
		 *
		 * PolicyQualifierInfo ::= ASN1Sequence
		 * {
		 *      policyQualifierId PolicyQualifierId,
		 *      qualifier ANY DEFINED BY policyQualifierId
		 * }
		 *
		 * PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
		 *
		 * Qualifier ::= CHOICE
		 * {
		 *      cPSuri CPSuri,
		 *      userNotice UserNotice
		 * }
		 *
		 * CPSuri ::= DERIA5String
		 *
		 * UserNotice ::= ASN1Sequence
		 * {
		 *      noticeRef NoticeReference OPTIONAL,
		 *      explicitText DisplayText OPTIONAL
		 * }
		 *
		 * NoticeReference ::= ASN1Sequence
		 * {
		 *      organization DisplayText,
		 *      noticeNumbers ASN1Sequence OF ASN1Integer
		 * }
		 *
		 * DisplayText ::= CHOICE
		 * {
		 *      ia5String DERIA5String (SIZE (1..200)),
		 *      visibleString VisibleString (SIZE (1..200)),
		 *      bmpString BMPString (SIZE (1..200)),
		 *      utf8String UTF8String (SIZE (1..200))
		 * }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);

		int certPolicy = 0;

		for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
			certPolicy++;

			sb.append(MessageFormat.format(res.getString("CertificatePolicy"), certPolicy));
			sb.append(NEWLINE);

			ASN1ObjectIdentifier policyIdentifier = policyInformation.getPolicyIdentifier();
			String policyIdentifierStr = ObjectIdUtil.toString(policyIdentifier);

			sb.append(INDENT);
			sb.append(MessageFormat.format(res.getString("PolicyIdentifier"), policyIdentifierStr));
			sb.append(NEWLINE);

			ASN1Sequence policyQualifiers = policyInformation.getPolicyQualifiers();

			if (policyQualifiers != null) { // Optional
				int policyQual = 0;

				for (ASN1Encodable policyQualifier : policyQualifiers.toArray()) {

					ASN1Sequence policyQualifierInfo = (ASN1Sequence) policyQualifier;

					sb.append(INDENT.toString(1));
					sb.append(MessageFormat.format(res.getString("PolicyQualifierInformation"), certPolicy,
							++policyQual));
					sb.append(NEWLINE);

					ASN1ObjectIdentifier policyQualifierId = (ASN1ObjectIdentifier) policyQualifierInfo.getObjectAt(0);

					CertificatePolicyQualifierType certificatePolicyQualifierType = CertificatePolicyQualifierType
							.resolveOid(policyQualifierId.getId());

					if (certificatePolicyQualifierType != null) {
						sb.append(INDENT.toString(2));
						sb.append(certificatePolicyQualifierType.friendly());
						sb.append(NEWLINE);

						if (certificatePolicyQualifierType == PKIX_CPS_POINTER_QUALIFIER) {
							DERIA5String cpsPointer = (DERIA5String) policyQualifierInfo.getObjectAt(1);

							sb.append(INDENT.toString(2));
							sb.append(MessageFormat.format(res.getString("CpsPointer"),
									"<a href=\"" + cpsPointer + "\">" + cpsPointer + "</a>"));
							sb.append(NEWLINE);
						} else if (certificatePolicyQualifierType == PKIX_USER_NOTICE_QUALIFIER) {
							ASN1Encodable userNoticeObj = policyQualifierInfo.getObjectAt(1);

							UserNotice userNotice = UserNotice.getInstance(userNoticeObj);

							sb.append(INDENT.toString(2));
							sb.append(res.getString("UserNotice"));
							sb.append(NEWLINE);

							NoticeReference noticeReference = userNotice.getNoticeRef();

							DisplayText explicitText = userNotice.getExplicitText();

							if (noticeReference != null) { // Optional
								sb.append(INDENT.toString(3));
								sb.append(res.getString("NoticeReference"));
								sb.append(NEWLINE);

								DisplayText organization = noticeReference.getOrganization();
								String organizationString = organization.getString();

								sb.append(INDENT.toString(4));
								sb.append(MessageFormat.format(res.getString("Organization"), organizationString));
								sb.append(NEWLINE);

								ASN1Integer[] noticeNumbers = noticeReference.getNoticeNumbers();

								StringBuilder sbNoticeNumbers = new StringBuilder();
								for (ASN1Integer noticeNumber : noticeNumbers) {
									sbNoticeNumbers.append(noticeNumber.getValue().intValue());
									sbNoticeNumbers.append(", ");
								}
								sbNoticeNumbers.setLength(sbNoticeNumbers.length() - 2);

								sb.append(INDENT.toString(4));
								sb.append(MessageFormat.format(res.getString("NoticeNumbers"),
										sbNoticeNumbers.toString()));
								sb.append(NEWLINE);
							}

							if (explicitText != null) { // Optional
								String explicitTextString = explicitText.getString();

								sb.append(INDENT.toString(3));
								sb.append(MessageFormat.format(res.getString("ExplicitText"), explicitTextString));
								sb.append(NEWLINE);
							}
						}
					}
				}
			}
		}

		return sb.toString();
	}

	private String getPolicyMappingsStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * PolicyMappings ::= ASN1Sequence SIZE (1..MAX) OF PolicyMappings
		 *
		 * PolicyMappings ::= ASN1Sequence { issuerDomainPolicy CertPolicyId,
		 * subjectDomainPolicy CertPolicyId }
		 *
		 * CertPolicyId ::= OBJECT IDENTIFIER
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		PolicyMappings policyMappings = PolicyMappings.getInstance(value);
		ASN1Sequence policyMappingsSeq = (ASN1Sequence) policyMappings.toASN1Primitive();

		int polMap = 0;

		for (ASN1Encodable policyMapping : policyMappingsSeq.toArray()) {

			ASN1Sequence policyMappingSeq = ASN1Sequence.getInstance(policyMapping.toASN1Primitive());
			polMap++;

			sb.append(MessageFormat.format(res.getString("PolicyMapping"), polMap));
			sb.append(NEWLINE);

			ASN1ObjectIdentifier issuerDomainPolicy = (ASN1ObjectIdentifier) policyMappingSeq.getObjectAt(0);
			ASN1ObjectIdentifier subjectDomainPolicy = (ASN1ObjectIdentifier) policyMappingSeq.getObjectAt(1);

			sb.append(INDENT);
			sb.append(MessageFormat.format(res.getString("IssuerDomainPolicy"),
					ObjectIdUtil.toString(issuerDomainPolicy)));
			sb.append(NEWLINE);

			sb.append(INDENT);
			sb.append(MessageFormat.format(res.getString("SubjectDomainPolicy"),
					ObjectIdUtil.toString(subjectDomainPolicy)));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getAuthorityKeyIdentifierStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * AuthorityKeyIdentifier ::= ASN1Sequence { keyIdentifier [0]
		 * KeyIdentifier OPTIONAL, authorityCertIssuer [1] GeneralNames
		 * OPTIONAL, authorityCertSerialNumber [2] CertificateSerialNumber
		 * OPTIONAL }
		 *
		 * KeyIdentifier ::= OCTET STRING
		 *
		 * GeneralNames ::= ASN1Sequence SIZE (1..MAX) OF GeneralName
		 *
		 * CertificateSerialNumber ::= ASN1Integer
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(value);

		byte[] keyIdentifier = authorityKeyIdentifier.getKeyIdentifier();
		GeneralNames authorityCertIssuer = authorityKeyIdentifier.getAuthorityCertIssuer();
		BigInteger certificateSerialNumber = authorityKeyIdentifier.getAuthorityCertSerialNumber();

		if (keyIdentifier != null) { // Optional
			// Output as a hex string
			sb.append(MessageFormat.format(res.getString("AuthorityKeyIdentifier"),
					HexUtil.getHexString(keyIdentifier)));
			sb.append(NEWLINE);
		}

		if (authorityCertIssuer != null) { // Optional
			sb.append(res.getString("CertificateIssuer"));
			sb.append(NEWLINE);

			for (GeneralName generalName : authorityCertIssuer.getNames()) {
				sb.append(INDENT);
				sb.append(GeneralNameUtil.toString(generalName));
				sb.append(NEWLINE);
			}
		}

		if (certificateSerialNumber != null) { // Optional
			// Output as an integer
			sb.append(MessageFormat.format(res.getString("CertificateSerialNumber"),
					HexUtil.getHexString(certificateSerialNumber)));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getPolicyConstraintsStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * PolicyConstraints ::= ASN1Sequence { requireExplicitPolicy [0]
		 * SkipCerts OPTIONAL, inhibitPolicyMapping [1] SkipCerts OPTIONAL }
		 *
		 * SkipCerts ::= ASN1Integer (0..MAX)
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		PolicyConstraints policyConstraints = PolicyConstraints.getInstance(value);

		int requireExplicitPolicy = policyConstraints.getRequireExplicitPolicy();
		int inhibitPolicyMapping = policyConstraints.getInhibitPolicyMapping();

		if (requireExplicitPolicy != -1) { // Optional
			sb.append(MessageFormat.format(res.getString("RequireExplicitPolicy"), requireExplicitPolicy));
			sb.append(NEWLINE);
		}

		if (inhibitPolicyMapping != -1) { // Optional
			sb.append(MessageFormat.format(res.getString("InhibitPolicyMapping"), inhibitPolicyMapping));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getExtendedKeyUsageStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * ExtendedKeyUsage ::= ASN1Sequence SIZE (1..MAX) OF KeyPurposeId
		 *
		 * KeyPurposeId ::= OBJECT IDENTIFIER
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(value);

		for (KeyPurposeId keyPurposeId : extendedKeyUsage.getUsages()) {
			String oid = keyPurposeId.getId();

			ExtendedKeyUsageType type = ExtendedKeyUsageType.resolveOid(oid);

			if (type != null) {
				sb.append(type.friendly());
			} else {
				// Unrecognised key purpose ID
				sb.append(oid);
			}

			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getFreshestCrlStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * FreshestCRL ::= CRLDistributionPoints
		 *
		 * CRLDistributionPoints ::= ASN1Sequence SIZE (1..MAX) OF
		 * DistributionPoint
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		CRLDistributionPoints freshestCRL = CRLDistributionPoints.getInstance(value);

		int distPoint = 0;

		for (DistributionPoint distributionPoint : freshestCRL.getDistributionPointList()) {
			distPoint++;

			sb.append(MessageFormat.format(res.getString("FreshestCrlDistributionPoint"), distPoint));
			sb.append(NEWLINE);

			sb.append(getDistributionPointString(distributionPoint, INDENT.toString(1)));
		}

		return sb.toString();
	}

	private String getInhibitAnyPolicyStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * InhibitAnyPolicy ::= SkipCerts
		 *
		 * SkipCerts ::= ASN1Integer (0..MAX)
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		InhibitAnyPolicy inhibitAnyPolicy = InhibitAnyPolicy.getInstance(value);

		int skipCerts = inhibitAnyPolicy.getSkipCerts();

		sb.append(MessageFormat.format(res.getString("InhibitAnyPolicy"), skipCerts));
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getNetscapeCertificateTypeStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * NetscapeCertType ::= BIT STRING { sslClient (0), sslServer (1), smime
		 * (2), objectSigning (3), reserved (4), sslCA (5), smimeCA (6),
		 * objectSigningCA (7) }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		@SuppressWarnings("resource") // we have a ByteArrayInputStream here which does not need to be closed
		DERBitString netscapeCertType = DERBitString.getInstance(new ASN1InputStream(value).readObject());

		int netscapeCertTypes = netscapeCertType.intValue();

		if (isCertType(netscapeCertTypes, NetscapeCertType.sslClient)) {
			sb.append(res.getString("SslClientNetscapeCertificateType"));
			sb.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.sslServer)) {
			sb.append(res.getString("SslServerNetscapeCertificateType"));
			sb.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.smime)) {
			sb.append(res.getString("SmimeNetscapeCertificateType"));
			sb.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.objectSigning)) {
			sb.append(res.getString("ObjectSigningNetscapeCertificateType"));
			sb.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.reserved)) {
			sb.append(res.getString("ReservedNetscapeCertificateType"));
			sb.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.sslCA)) {
			sb.append(res.getString("SslCaNetscapeCertificateType"));
			sb.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.smimeCA)) {
			sb.append(res.getString("SmimeCaNetscapeCertificateType"));
			sb.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.objectSigningCA)) {
			sb.append(res.getString("ObjectSigningCaNetscapeCertificateType"));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private boolean isCertType(int netscapeCertTypes, int certType) {
		return (netscapeCertTypes & certType) == certType;
	}

	private String getNetscapeBaseUrlStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeBaseUrl ::= DERIA5String */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		DERIA5String netscapeBaseUrl = DERIA5String.getInstance(value);

		sb.append(netscapeBaseUrl.getString());
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getNetscapeRevocationUrlStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeRevocationUrl ::= DERIA5String */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		DERIA5String netscapeRevocationUrl = DERIA5String.getInstance(value);

		sb.append(netscapeRevocationUrl.getString());
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getNetscapeCaRevocationUrlStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeCARevocationUrl ::= DERIA5String */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		DERIA5String netscapeCaRevocationUrl = DERIA5String.getInstance(value);

		sb.append(netscapeCaRevocationUrl.getString());
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getNetscapeCertificateRenewalStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeCertRenewalUrl ::= DERIA5String */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		DERIA5String netscapeCertRenewalUrl = DERIA5String.getInstance(value);

		sb.append(netscapeCertRenewalUrl.getString());
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getNetscapeCaPolicyUrlStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeCAPolicyUrl ::= DERIA5String */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		DERIA5String netscapeCaPolicyUrl = DERIA5String.getInstance(value);

		sb.append(netscapeCaPolicyUrl.getString());
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getNetscapeSslServerNameStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeSslServerName ::= DERIA5String */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		DERIA5String netscapeSslServerName = DERIA5String.getInstance(value);

		sb.append(netscapeSslServerName.getString());
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getNetscapeCommentStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeComment ::= DERIA5String */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		DERIA5String netscapeComment = DERIA5String.getInstance(value);

		sb.append(netscapeComment.getString());
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getDistributionPointString(DistributionPoint distributionPoint, String baseIndent)
			throws IOException {
		// @formatter:off

		/*
		 * DistributionPoint ::= ASN1Sequence {
		 * 		distributionPoint [0] DistributionPointName OPTIONAL,
		 * 		reasons [1] ReasonFlags OPTIONAL,
		 * 		cRLIssuer [2] GeneralNames OPTIONAL
		 * }
		 *
		 * GeneralNames ::= ASN1Sequence SIZE (1..MAX) OF GeneralName
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
		ReasonFlags reasons = distributionPoint.getReasons();
		GeneralNames crlIssuer = distributionPoint.getCRLIssuer();

		if (distributionPointName != null) { // Optional
			sb.append(getDistributionPointNameString(distributionPointName, baseIndent));
		}

		if (reasons != null) { // Optional
			sb.append(baseIndent);
			sb.append(res.getString("DistributionPointReasons"));
			sb.append(NEWLINE);

			String[] reasonFlags = getReasonFlagsStrings(reasons);

			for (String reasonFlag : reasonFlags) {
				sb.append(baseIndent);
				sb.append(INDENT);
				sb.append(reasonFlag);
				sb.append(NEWLINE);
			}
		}

		if (crlIssuer != null) { // Optional
			sb.append(baseIndent);
			sb.append(res.getString("DistributionPointCrlIssuer"));
			sb.append(NEWLINE);

			for (GeneralName generalName : crlIssuer.getNames()) {
				sb.append(baseIndent);
				sb.append(INDENT);
				sb.append(GeneralNameUtil.toString(generalName));
				sb.append(NEWLINE);
			}
		}

		return sb.toString();
	}

	private String getDistributionPointNameString(DistributionPointName distributionPointName, String baseIndent)
			throws IOException {
		// @formatter:off

		/*
		 * DistributionPointName ::= CHOICE {
		 * 		fullname [0] GeneralNames,
		 * 		nameRelativeToCRLIssuer [1] RelativeDistinguishedName
		 * }
		 *
		 * RelativeDistinguishedName ::= SET SIZE (1 .. MAX) OF
		 * AttributeTypeAndValue
		 *
		 * AttributeTypeAndValue ::= ASN1Sequence { type AttributeType, value
		 * AttributeValue }
		 */

		// @formatter: on

		StringBuilder sb = new StringBuilder();

		sb.append(baseIndent);
		sb.append(res.getString("DistributionPointName"));
		sb.append(NEWLINE);

		if (distributionPointName.getType() == DistributionPointName.FULL_NAME) {
			sb.append(baseIndent);
			sb.append(INDENT);
			sb.append(res.getString("DistributionPointFullName"));
			sb.append(NEWLINE);

			GeneralNames generalNames = GeneralNames.getInstance(distributionPointName.getName());

			for (GeneralName generalName : generalNames.getNames()) {
				sb.append(baseIndent);
				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(GeneralNameUtil.toString(generalName));
				sb.append(NEWLINE);
			}
		} else {
			// DistributionPointName.TAG_NAMERELATIVETOCRLISSUER
			sb.append(baseIndent);
			sb.append(INDENT);
			sb.append(res.getString("DistributionPointNameRelativeToCrlIssuer"));
			sb.append(NEWLINE);

			RDN rdn = RDN.getInstance(distributionPointName.getName());

			for (AttributeTypeAndValue attributeTypeAndValue : rdn.getTypesAndValues()) {
				ASN1ObjectIdentifier attributeType = attributeTypeAndValue.getType();
				ASN1Encodable attributeValue = attributeTypeAndValue.getValue();

				String attributeTypeStr = getAttributeTypeString(attributeType);
				String attributeValueStr = getAttributeValueString(attributeType, attributeValue);

				sb.append(baseIndent);
				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(MessageFormat.format("{0}={1}", attributeTypeStr, attributeValueStr));
				sb.append(NEWLINE);
			}
		}

		return sb.toString();
	}

	private String[] getReasonFlagsStrings(ReasonFlags reasonFlags) throws IOException {
		// @formatter:off

		/*
		 * ReasonFlags ::= BIT STRING { unused(0), keyCompromise(1),
		 * cACompromise(2), affiliationChanged(3), superseded(4),
		 * cessationOfOperation(5), certificateHold(6), privilegeWithdrawn(7),
		 * aACompromise(8)}
		 */

		// @formatter:on

		List<String> reasonFlagsList = new ArrayList<String>();

		DERBitString reasonFlagsBitString = (DERBitString) reasonFlags.toASN1Primitive();

		int reasonFlagsInt = reasonFlagsBitString.intValue();

		// Go through bit string adding reason flags found to be true
		if (hasReasonFlag(reasonFlagsInt, ReasonFlags.unused)) {
			reasonFlagsList.add(res.getString("UnusedReasonFlag"));
		}
		if (hasReasonFlag(reasonFlagsInt, ReasonFlags.keyCompromise)) {
			reasonFlagsList.add(res.getString("KeyCompromiseReasonFlag"));
		}
		if (hasReasonFlag(reasonFlagsInt, ReasonFlags.cACompromise)) {
			reasonFlagsList.add(res.getString("CaCompromiseReasonFlag"));
		}
		if (hasReasonFlag(reasonFlagsInt, ReasonFlags.affiliationChanged)) {
			reasonFlagsList.add(res.getString("AffiliationChangedReasonFlag"));
		}
		if (hasReasonFlag(reasonFlagsInt, ReasonFlags.superseded)) {
			reasonFlagsList.add(res.getString("SupersededReasonFlag"));
		}
		if (hasReasonFlag(reasonFlagsInt, ReasonFlags.cessationOfOperation)) {
			reasonFlagsList.add(res.getString("CessationOfOperationReasonFlag"));
		}
		if (hasReasonFlag(reasonFlagsInt, ReasonFlags.certificateHold)) {
			reasonFlagsList.add(res.getString("CertificateHoldReasonFlag"));
		}
		if (hasReasonFlag(reasonFlagsInt, ReasonFlags.privilegeWithdrawn)) {
			reasonFlagsList.add(res.getString("PrivilegeWithdrawnReasonFlag"));
		}
		if (hasReasonFlag(reasonFlagsInt, ReasonFlags.aACompromise)) {
			reasonFlagsList.add(res.getString("AaCompromiseReasonFlag"));
		}

		return reasonFlagsList.toArray(new String[reasonFlagsList.size()]);
	}

	private boolean hasReasonFlag(int reasonFlags, int reasonFlag) {
		return (reasonFlags & reasonFlag) == reasonFlag;
	}

	private String getAttributeTypeString(ASN1ObjectIdentifier oid) {
		// @formatter:off

		/* AttributeType ::= OBJECT IDENTIFIER */

		// @formatter:on

		AttributeTypeType attributeTypeType = AttributeTypeType.resolveOid(oid.getId());

		if (attributeTypeType != null) {
			return attributeTypeType.friendly();
		}
		// Attribute type not recognized - return formatted OID string
		else {
			return ObjectIdUtil.toString(oid);
		}
	}

	private String getAttributeValueString(ASN1ObjectIdentifier attributeType, ASN1Encodable attributeValue)
			throws IOException {

		/* AttributeValue ::= ANY */

		// Get value string for recognized attribute types
		AttributeTypeType attributeTypeType = AttributeTypeType.resolveOid(attributeType.getId());

		switch (attributeTypeType) {
		case COMMON_NAME:
			return DirectoryString.getInstance(attributeValue).getString();
		case SERIAL_NUMBER:
		case UNSTRUCTURED_ADDRESS:
			return DERPrintableString.getInstance(attributeValue).getString();
		case COUNTRY_NAME:
			return DERPrintableString.getInstance(attributeValue).getString();
		case LOCALITY_NAME:
			return DirectoryString.getInstance(attributeValue).getString();
		case STATE_NAME:
			return DirectoryString.getInstance(attributeValue).getString();
		case STREET_ADDRESS:
			return DirectoryString.getInstance(attributeValue).getString();
		case ORGANIZATION_NAME:
			return DirectoryString.getInstance(attributeValue).getString();
		case ORGANIZATIONAL_UNIT:
			return DirectoryString.getInstance(attributeValue).getString();
		case TITLE:
		case USER_ID:
			return DirectoryString.getInstance(attributeValue).getString();
		case MAIL:
		case EMAIL_ADDRESS:
		case UNSTRUCTURED_NAME:
			return DERIA5String.getInstance(attributeValue).getString();
		case DOMAIN_COMPONENT:
			return DERIA5String.getInstance(attributeValue).getString();
		default:
			// Attribute type not recognized - return hex string for value
			return HexUtil.getHexString(attributeValue.toASN1Primitive().getEncoded());
		}
	}

	private String getGeneralizedTimeString(ASN1GeneralizedTime notBefore) {
		// Get generalized time as a date
		Date date;
		try {
			date = notBefore.getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException("Cannot parse date");
		}

		return StringUtils.formatDate(date);
	}

	private String getBiometricInfoStringValue(byte[] octets) {

		// @formatter:off

		/*
			BiometricSyntax ::= SEQUENCE OF BiometricData
			BiometricData ::= SEQUENCE
			{
				typeOfBiometricData TypeOfBiometricData,
				hashAlgorithm AlgorithmIdentifier,
				biometricDataHash OCTET STRING,
				sourceDataUri IA5String OPTIONAL
			}
			TypeOfBiometricData ::= CHOICE
			{
				predefinedBiometricType PredefinedBiometricType,
				biometricDataId OBJECT IDENTIIFER
			}
			PredefinedBiometricType ::= INTEGER
			{
				picture(0),
				handwritten-signature(1)
			}
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();
		int biometricDataNr = 0;

		ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(octets);

		for (ASN1Encodable asn1Encodable : asn1Sequence.toArray()) {
			BiometricData biometricData = BiometricData.getInstance(asn1Encodable);
			TypeOfBiometricData typeOfBiometricData = biometricData.getTypeOfBiometricData();
			AlgorithmIdentifier hashAlgorithm = biometricData.getHashAlgorithm();
			ASN1OctetString biometricDataHash = biometricData.getBiometricDataHash();
			DERIA5String sourceDataUri = biometricData.getSourceDataUri();

			sb.append(MessageFormat.format(res.getString("BiometricInfo.BiometricData"), biometricDataNr));
			sb.append(NEWLINE);

			sb.append(INDENT);
			if (typeOfBiometricData.isPredefined()) {
				int type = typeOfBiometricData.getPredefinedBiometricType();
				sb.append(MessageFormat.format(res.getString("BiometricInfo.TypeOfBiometricData"), type));
			} else {
				String biometricDataOid = typeOfBiometricData.getBiometricDataOid().getId();
				sb.append(MessageFormat.format(res.getString("BiometricInfo.TypeOfBiometricData"), biometricDataOid));
			}
			sb.append(NEWLINE);

			sb.append(INDENT);
			sb.append(MessageFormat.format(res.getString("BiometricInfo.HashAlgorithm"),
					hashAlgorithm.getAlgorithm().getId()));
			sb.append(NEWLINE);

			sb.append(INDENT);
			sb.append(MessageFormat.format(res.getString("BiometricInfo.BiometricDataHash"),
					HexUtil.getHexString(biometricDataHash.getOctets())));
			sb.append(NEWLINE);

			if (sourceDataUri != null) { // optional
				sb.append(INDENT);
				sb.append(MessageFormat.format(res.getString("BiometricInfo.SourceDataUri"), sourceDataUri.toString()));
				sb.append(NEWLINE);
			}
		}

		return sb.toString();
	}

	private String getQcStatementsStringValue(byte[] octets) throws IOException {

		// @formatter:off

		/*
			QCStatements ::= SEQUENCE OF QSStatement
		    QSStatement ::= SEQUENCE
		    {
		        statementId OBJECT IDENTIFIER,
		        statementInfo ANY DEFINED BY statementId OPTIONAL
		    }
		    QcEuLimitValue ::= MonetaryValue
			QcRetentionPeriod ::= INTEGER
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		int qcStatementNr = 0;

		ASN1Sequence qcStatements = ASN1Sequence.getInstance(octets);
		for (ASN1Encodable asn1Encodable : qcStatements.toArray()) {
			QCStatement qcStatement = QCStatement.getInstance(asn1Encodable);
			ASN1ObjectIdentifier statementId = qcStatement.getStatementId();
			ASN1Encodable statementInfo = qcStatement.getStatementInfo();

			int indentLevel = 1;

			sb.append(MessageFormat.format(res.getString("QCStatement.QCStatement"), ++qcStatementNr));
			sb.append(NEWLINE);

			QcStatementType qcStatementType = QcStatementType.resolveOid(statementId.getId());
			if (qcStatementType != null) {
				switch (qcStatementType) {
				case QC_SYNTAX_V1:
				case QC_SYNTAX_V2:
					SemanticsInformation semanticsInfo = SemanticsInformation.getInstance(statementInfo);
					sb.append(getSemanticInformationValueString(qcStatementType, semanticsInfo, indentLevel));
					break;
				case QC_COMPLIANCE:
					// no statementInfo
					sb.append(INDENT.toString(indentLevel));
					sb.append(res.getString(QcStatementType.QC_COMPLIANCE.getResKey()));
					sb.append(NEWLINE);
					break;
				case QC_EU_LIMIT_VALUE:
					sb.append(INDENT.toString(indentLevel));
					sb.append(res.getString(QcStatementType.QC_EU_LIMIT_VALUE.getResKey()));
					sb.append(NEWLINE);
					sb.append(getMonetaryValueStringValue(statementInfo, indentLevel + 1));
					break;
				case QC_RETENTION_PERIOD:
					ASN1Integer asn1Integer = ASN1Integer.getInstance(statementInfo);
					sb.append(INDENT.toString(indentLevel));
					sb.append(MessageFormat.format(res.getString(QcStatementType.QC_RETENTION_PERIOD.getResKey()),
							asn1Integer.getValue().toString()));
					sb.append(NEWLINE);
					break;
				case QC_SSCD:
					// no statementInfo
					sb.append(INDENT.toString(indentLevel));
					sb.append(res.getString(QcStatementType.QC_SSCD.getResKey()));
					sb.append(NEWLINE);
					break;
				case QC_PDS:
					ASN1Sequence pdsLocations = ASN1Sequence.getInstance(statementInfo);
					sb.append(INDENT.toString(indentLevel));
					sb.append(res.getString(QcStatementType.QC_PDS.getResKey()));
					for (ASN1Encodable pdsLoc : pdsLocations) {
						sb.append(NEWLINE);
						sb.append(INDENT.toString(indentLevel + 1));
						DLSequence pds = (DLSequence) pdsLoc;
						sb.append(MessageFormat.format(res.getString("QCPDS.locations"), pds.getObjectAt(1), pds.getObjectAt(0)));
					}
					sb.append(NEWLINE);
					break;
				case QC_TYPE:
					sb.append(INDENT.toString(indentLevel));
					sb.append(res.getString(QcStatementType.QC_TYPE.getResKey()));
					ASN1Sequence qcTypes = ASN1Sequence.getInstance(statementInfo);
					for (ASN1Encodable type : qcTypes) {
						sb.append(NEWLINE);
						sb.append(INDENT.toString(indentLevel + 1));
						sb.append(ObjectIdUtil.toString((ASN1ObjectIdentifier) type));
					}
					sb.append(NEWLINE);
				}
			} else {
				// unknown statement type
				sb.append(INDENT.toString(indentLevel));
				sb.append(ObjectIdUtil.toString(statementId));
				if (statementInfo != null) {
					sb.append(statementInfo.toString());
				}
				sb.append(NEWLINE);
			}
		}

		return sb.toString();

	}


	private String getSemanticInformationValueString(QcStatementType qcStatementType, SemanticsInformation
			semanticsInfo, int baseIndentLevel) throws IOException {

		// @formatter:off

		/*
		SemanticsInformation ::= SEQUENCE
		{
			semanticsIdentifier OBJECT IDENTIFIER OPTIONAL,
			nameRegistrationAuthorities NameRegistrationAuthorities OPTIONAL
		}
		NameRegistrationAuthorities ::= SEQUENCE SIZE(1..MAX) OF GeneralName
		 */

		// @formatter:on

		ASN1ObjectIdentifier semanticsIdentifier = semanticsInfo.getSemanticsIdentifier();
		GeneralName[] nameRegistrationAuthorities = semanticsInfo.getNameRegistrationAuthorities();

		StringBuilder sb = new StringBuilder();

		sb.append(INDENT.toString(baseIndentLevel));
		if (qcStatementType == QcStatementType.QC_SYNTAX_V1) {
			sb.append(res.getString(QcStatementType.QC_SYNTAX_V1.getResKey()));
		} else {
			sb.append(res.getString(QcStatementType.QC_SYNTAX_V2.getResKey()));
		}
		sb.append(NEWLINE);

		if (semanticsIdentifier != null) {
			sb.append(INDENT.toString(baseIndentLevel + 1));
			sb.append(MessageFormat.format(res.getString("QCSyntax.SemanticsIdentifier"),
					semanticsIdentifier.getId()));
			sb.append(NEWLINE);
		}

		if (nameRegistrationAuthorities != null) {
			sb.append(INDENT.toString(baseIndentLevel + 1));
			sb.append(res.getString("QCSyntax.NameRegistrationAuthorities"));
			sb.append(NEWLINE);

			for (GeneralName nameRegistrationAuthority : nameRegistrationAuthorities) {
				sb.append(INDENT.toString(baseIndentLevel + 2));
				sb.append(GeneralNameUtil.toString(nameRegistrationAuthority));
				sb.append(NEWLINE);
			}
		}

		return sb.toString();
	}

	private String getMonetaryValueStringValue(ASN1Encodable asn1Encodable, int baseIndentLevel) {

		// @formatter:off

		/*
		    MonetaryValue ::= SEQUENCE
		    {
		        currency Iso4217CurrencyCode,
		        amount INTEGER,
		        exponent INTEGER
		    }
		    Iso4217CurrencyCode ::= CHOICE
		    {
		        alphabetic PrintableString,
		        numeric INTEGER(1..999)
		    }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		MonetaryValue monetaryValue = MonetaryValue.getInstance(asn1Encodable);
		BigInteger amount = monetaryValue.getAmount();
		Iso4217CurrencyCode currency = monetaryValue.getCurrency();
		BigInteger exponent = monetaryValue.getExponent();

		if (currency != null) {
			String currencyString = currency.isAlphabetic() ? currency.getAlphabetic() : "" + currency.getNumeric();
			sb.append(INDENT.toString(baseIndentLevel));
			sb.append(MessageFormat.format(res.getString("QCEuLimitValue.Currency"), currencyString));
			sb.append(NEWLINE);
		}

		if (amount != null) {
			sb.append(INDENT.toString(baseIndentLevel));
			sb.append(MessageFormat.format(res.getString("QCEuLimitValue.Amount"), amount.toString()));
			sb.append(NEWLINE);
		}

		if (exponent != null) {
			sb.append(INDENT.toString(baseIndentLevel));
			sb.append(MessageFormat.format(res.getString("QCEuLimitValue.Exponent"), exponent.toString()));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getOcspNoCheckStringValue(byte[] octets) {

		/*	OCSPNoCheck ::= NULL */

		// we return the extension name as the value, because only its existence matters and 'NULL' might be confusing
		return res.getString("OCSPNoCheck");
	}

	private String getAdmissionStringValue(byte[] octets) throws IOException {

		// @formatter:off

		/*
			 AdmissionSyntax ::= SEQUENCE
		     {
		       admissionAuthority GeneralName OPTIONAL,
		       contentsOfAdmissions SEQUENCE OF Admissions
		     }
		     Admissions ::= SEQUENCE
		     {
		       admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
		       namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
		       professionInfos SEQUENCE OF ProfessionInfo
		     }
		     NamingAuthority ::= SEQUENCE
		     {
		       namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
		       namingAuthorityUrl IA5String OPTIONAL,
		       namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
		     }
		     ProfessionInfo ::= SEQUENCE
		     {
		       namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
		       professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
		       professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
		       registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
		       addProfessionInfo OCTET STRING OPTIONAL
		     }
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();
		int indentLevel = 1;

		AdmissionSyntax admissionSyntax = AdmissionSyntax.getInstance(ASN1Sequence.getInstance(octets));
		GeneralName admissionAuthority = admissionSyntax.getAdmissionAuthority();

		if (admissionAuthority != null) {
			sb.append(MessageFormat.format(res.getString("Admission.AdmissionAuthority"),
					GeneralNameUtil.toString(admissionAuthority)));
			sb.append(NEWLINE);
		}

		Admissions[] admissions = admissionSyntax.getContentsOfAdmissions();
		int admissionNr = 0;
		for (Admissions admission : admissions) {
			sb.append(MessageFormat.format(res.getString("Admission.Admission"), ++admissionNr));
			sb.append(NEWLINE);

			admissionAuthority = admission.getAdmissionAuthority();
			NamingAuthority namingAuthority = admission.getNamingAuthority();
			ProfessionInfo[] professionInfos = admission.getProfessionInfos();

			if (admissionAuthority != null) {
				sb.append(INDENT.toString(indentLevel));
				sb.append(MessageFormat.format(res.getString("Admission.AdmissionAuthority"),
						GeneralNameUtil.toString(admissionAuthority)));
				sb.append(NEWLINE);
			}

			if (namingAuthority != null) {
				sb.append(getNamingAuthorityStringValue(namingAuthority, indentLevel));
			}

			for (ProfessionInfo professionInfo : professionInfos) {

				namingAuthority = professionInfo.getNamingAuthority();
				ASN1ObjectIdentifier[] professionOIDs = professionInfo.getProfessionOIDs();
				String registrationNumber = professionInfo.getRegistrationNumber();
				ASN1OctetString addProfessionInfo = professionInfo.getAddProfessionInfo();

				sb.append(INDENT.toString(indentLevel));
				sb.append(res.getString("Admission.ProfessionInfo"));
				sb.append(NEWLINE);
				indentLevel++;

				if (namingAuthority != null) {
					sb.append(getNamingAuthorityStringValue(namingAuthority, indentLevel));
				}

				DirectoryString[] professionItems = professionInfo.getProfessionItems();
				for (DirectoryString professionItem : professionItems) {
					sb.append(INDENT.toString(indentLevel));
					sb.append(MessageFormat.format(res.getString("Admission.ProfessionItem"),
							professionItem.toString()));
					sb.append(NEWLINE);
				}

				if (professionOIDs != null) {
					for (ASN1ObjectIdentifier professionOID : professionOIDs) {
						sb.append(INDENT.toString(indentLevel));
						sb.append(MessageFormat.format(res.getString("Admission.ProfessionOID"),
								professionOID.getId()));
						sb.append(NEWLINE);
					}
				}

				if (registrationNumber != null) {
					sb.append(INDENT.toString(indentLevel));
					sb.append(MessageFormat.format(res.getString("Admission.RegistrationNumber"),
							registrationNumber));
					sb.append(NEWLINE);
				}

				if (addProfessionInfo != null) {
					sb.append(INDENT.toString(indentLevel));
					sb.append(MessageFormat.format(res.getString("Admission.AddProfessionInfo"),
							HexUtil.getHexString(addProfessionInfo.getOctets())));
					sb.append(NEWLINE);
				}

				indentLevel--;
			}
		}

		return sb.toString();
	}

	private String getNamingAuthorityStringValue(NamingAuthority namingAuthority, int indentLevel)
			throws IOException {
		// @formatter:off
		/*
		     NamingAuthority ::= SEQUENCE
		     {
		       namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
		       namingAuthorityUrl IA5String OPTIONAL,
		       namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
		     }
		 */
		// @formatter:on

		StringBuilder sb = new StringBuilder();

		ASN1ObjectIdentifier namingAuthorityId = namingAuthority.getNamingAuthorityId();
		String namingAuthorityUrl = namingAuthority.getNamingAuthorityUrl();
		DirectoryString namingAuthorityText = namingAuthority.getNamingAuthorityText();

		if (namingAuthorityId != null) {
			sb.append(INDENT.toString(indentLevel));
			sb.append(MessageFormat.format(res.getString("Admission.NamingAuthorityOID"), namingAuthorityId.getId()));
			sb.append(NEWLINE);
		}

		if (namingAuthorityUrl != null) {
			sb.append(INDENT.toString(indentLevel));
			sb.append(MessageFormat.format(res.getString("Admission.NamingAuthorityURL"), namingAuthorityUrl));
			sb.append(NEWLINE);
		}

		if (namingAuthorityText != null) {
			sb.append(INDENT.toString(indentLevel));
			sb.append(MessageFormat.format(res.getString("Admission.NamingAuthorityText"),
					namingAuthorityText.toString()));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getLiabilityLimitationFlagStringValue(byte[] octets) {

		/*	LiabilityLimitationFlagSyntax ::= BOOLEAN */

		ASN1Boolean asn1Boolean = ASN1Boolean.getInstance(octets);
		return asn1Boolean.toString();
	}

	private String getDateOfCertGenStringValue(byte[] octets) {

		/*	DateOfCertGenSyntax ::= GeneralizedTime */

		ASN1GeneralizedTime dateOfCertGenSyntax = ASN1GeneralizedTime.getInstance(octets);
		return getGeneralizedTimeString(dateOfCertGenSyntax);
	}

	private String getProcurationStringValue(byte[] octets) throws IOException {

		// @formatter:off

		/*
			ProcurationSyntax ::= SEQUENCE
			{
				country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
				typeOfSubstitution [2] EXPLICIT DirectoryString(SIZE(1..128)) OPTIONAL,
				signingFor [3] EXPLICIT SigningFor
			}

			SigningFor ::= CHOICE
			{
				thirdPerson GeneralName,
				certRef IssuerSerial
			}
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		ProcurationSyntax procurationSyntax = ProcurationSyntax.getInstance(octets);
		String country = procurationSyntax.getCountry();
		DirectoryString typeOfSubstitution = procurationSyntax.getTypeOfSubstitution();
		GeneralName thirdPerson = procurationSyntax.getThirdPerson();
		IssuerSerial certRef = procurationSyntax.getCertRef();

		if (country != null) {
			sb.append(MessageFormat.format(res.getString("Procuration.Country"), country));
			sb.append(NEWLINE);
		}

		if (typeOfSubstitution != null) {
			sb.append(MessageFormat.format(res.getString("Procuration.TypeOfSubstitution"),
					typeOfSubstitution.toString()));
			sb.append(NEWLINE);
		}

		if (thirdPerson != null) {
			sb.append(MessageFormat.format(res.getString("Procuration.ThirdPerson"),
					GeneralNameUtil.toString(thirdPerson)));
			sb.append(NEWLINE);
		}

		if (certRef != null) {
			sb.append(res.getString("Procuration.CertRef"));
			sb.append(NEWLINE);

			sb.append(INDENT);
			sb.append(res.getString("Procuration.CertRef.Issuer"));
			for (GeneralName generalName : certRef.getIssuer().getNames()) {
				sb.append(INDENT);
				sb.append(INDENT);
				sb.append(GeneralNameUtil.toString(generalName));
				sb.append(NEWLINE);
			}
			sb.append(NEWLINE);

			sb.append(INDENT);
			sb.append(MessageFormat.format(res.getString("Procuration.CertRef.SN"),
					HexUtil.getHexString(certRef.getSerial().getValue())));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getMonetaryLimitStringValue(byte[] octets) {

		// @formatter:off

		/*
			MonetaryLimitSyntax ::= SEQUENCE
			{
				currency PrintableString (SIZE(3)),
				amount INTEGER,
				exponent INTEGER
			}
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		MonetaryLimit monetaryLimit = MonetaryLimit.getInstance(octets);
		String currency = monetaryLimit.getCurrency();
		BigInteger amount = monetaryLimit.getAmount();
		BigInteger exponent = monetaryLimit.getExponent();

		if (currency != null) {
			sb.append(MessageFormat.format(res.getString("MonetaryLimit.Currency"), currency));
			sb.append(NEWLINE);
		}

		if (amount != null) {
			sb.append(MessageFormat.format(res.getString("MonetaryLimit.Amount"), amount.toString()));
			sb.append(NEWLINE);
		}

		if (exponent != null) {
			sb.append(MessageFormat.format(res.getString("MonetaryLimit.Exponent"), exponent.toString()));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getDeclarationOfMajorityStringValue(byte[] octets) {

		// @formatter:off

		/*
			DeclarationOfMajoritySyntax ::= CHOICE
			{
				notYoungerThan [0] IMPLICIT INTEGER,
				fullAgeAtCountry [1] IMPLICIT SEQUENCE {
					fullAge BOOLEAN DEFAULT TRUE,
					country PrintableString (SIZE(2))
				},
				dateOfBirth [2] IMPLICIT GeneralizedTime
			}
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		DeclarationOfMajority declarationOfMajority = DeclarationOfMajority.getInstance(octets);
		int notYoungerThan = declarationOfMajority.notYoungerThan();
		ASN1Sequence fullAgeAtCountry = declarationOfMajority.fullAgeAtCountry();
		ASN1GeneralizedTime dateOfBirth = declarationOfMajority.getDateOfBirth();

		if (notYoungerThan != -1) {
			sb.append(MessageFormat.format(res.getString("DeclarationOfMajority.notYoungerThan"), notYoungerThan));
			sb.append(NEWLINE);
		}

		if (fullAgeAtCountry != null) {
			ASN1Boolean fullAge = ASN1Boolean.getInstance(fullAgeAtCountry.getObjectAt(0));
			DERPrintableString country = DERPrintableString.getInstance(fullAgeAtCountry.getObjectAt(1));

			sb.append(MessageFormat.format(res.getString("DeclarationOfMajority.fullAgeAtCountry"), country.toString(),
					fullAge.toString()));
			sb.append(NEWLINE);
		}

		if (dateOfBirth != null) {
			sb.append(MessageFormat.format(res.getString("DeclarationOfMajority.dateOfBirth"), dateOfBirth));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getICCSNStringValue(byte[] octets) {

		/*	ICCSNSyntax ::= OCTET STRING (SIZE(8..20)) */

		return HexUtil.getHexString(octets);
	}

	private String getRestrictionStringValue(byte[] octets) throws IOException {

		/*	RestrictionSyntax ::= DirectoryString (SIZE(1..1024)) */

		return DirectoryString.getInstance(ASN1Primitive.fromByteArray(octets)).toString();
	}


	private String getAdditionalInformationStringValue(byte[] octets) throws IOException {

		/*	AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048)) */

		return DirectoryString.getInstance(ASN1Primitive.fromByteArray(octets)).toString();
	}


	private String getValidityModelStringValue(byte[] octets) {

		// @formatter:off

		/*
			ValidityModel::= SEQUENCE
			{
				validityModelId OBJECT IDENTIFIER
				validityModelInfo ANY DEFINED BY validityModelId OPTIONAL
			}
		 */

		// @formatter:on

		ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(octets);
		ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1Sequence.getObjectAt(0));
		ValidityModelType validityModel = ValidityModelType.resolveOid(oid.getId());

		return validityModel.friendly();
	}


	private String getMsCertTypeStringValue(byte[] octets) {

		// @formatter:off

		/*
			Not much information available about that extension...

			06 09		; OBJECT_ID (9 Bytes)
			|  2b 06 01 04 01 82 37 14  02
			|     ; 1.3.6.1.4.1.311.20.2 Certificate Template Name (Certificate Type)
			04 0a		; OCTET_STRING (a Bytes)#
			   1e 08 00 55 00 73 00 65  00 72                    ; ...U.s.e.r
		 */

		// @formatter:on

		DERBMPString derbmpString = DERBMPString.getInstance(octets);

		return derbmpString.toString();
	}


	private String getMsCaVersionStringValue(byte[] octets) {

		/*
            "The extension data is a DWORD value (encoded as X509_INTEGER in the extension);
            the low 16 bits are the certificate index, and the high 16 bits are the key index."
		 */

		ASN1Integer asn1Integer = ASN1Integer.getInstance(octets);
		int version = asn1Integer.getValue().intValue();
		String certIndex = String.valueOf(version & 0xffff);
		String keyIndex = String.valueOf(version >> 16);

		StringBuilder sb = new StringBuilder();

		sb.append(MessageFormat.format(res.getString("MSCaVersion.CertIndex"), certIndex));
		sb.append(NEWLINE);
		sb.append(MessageFormat.format(res.getString("MSCaVersion.KeyIndex"), keyIndex));
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String getMsCrlNextPublishStringValue(byte[] octets) {
		ASN1UTCTime time = ASN1UTCTime.getInstance(octets);
		return time.getTime();
	}

	private String getMsCertificateTemplateStringValue(byte[] octets) {

		// @formatter:off

		/*
			CertificateTemplate ::= SEQUENCE
			{
				templateID              EncodedObjectID,
				templateMajorVersion    TemplateVersion,
				templateMinorVersion    TemplateVersion OPTIONAL
			}
			TemplateVersion ::= INTEGER (0..4294967295)
		 */

		// @formatter:on

		ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(octets);
		ASN1ObjectIdentifier templateID = (ASN1ObjectIdentifier) asn1Sequence.getObjectAt(0);
		ASN1Integer majorVersion = (ASN1Integer) asn1Sequence.getObjectAt(1);
		ASN1Integer minorVersion = (ASN1Integer) asn1Sequence.getObjectAt(2);

		StringBuilder sb = new StringBuilder();

		sb.append(MessageFormat.format(res.getString("MSCertificateTemplate.ID"), templateID.getId()));
		sb.append(NEWLINE);

		sb.append(MessageFormat.format(res.getString("MSCertificateTemplate.MajorVersion"), majorVersion));
		sb.append(NEWLINE);

		if (minorVersion != null) {
			sb.append(MessageFormat.format(res.getString("MSCertificateTemplate.MinorVersion"), minorVersion));
			sb.append(NEWLINE);
		}

		return sb.toString();
	}

	private String getSMIMECapabilitiesStringValue(byte[] octets) throws IOException {

		// @formatter:off

		/*
			SMIMECapabilities ::= SEQUENCE OF SMIMECapability

			SMIMECapability ::= SEQUENCE
			{
				capabilityID OBJECT IDENTIFIER,
				parameters ANY DEFINED BY capabilityID OPTIONAL
			}
		 */

		// @formatter:on

		StringBuilder sb = new StringBuilder();

		int capabilityNr = 0;

		ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(octets);
		for (ASN1Encodable asn1Encodable : asn1Sequence.toArray()) {
			SMIMECapability capability = SMIMECapability.getInstance(asn1Encodable);
			ASN1ObjectIdentifier oid = capability.getCapabilityID();
			ASN1Encodable parameters = capability.getParameters();

			sb.append(MessageFormat.format(res.getString("SMIMECapability"), ++capabilityNr));
			sb.append(NEWLINE);

			sb.append(INDENT);
			sb.append(MessageFormat.format(res.getString("SMIMECapability.ObjectID"), ObjectIdUtil.toString(oid)));
			sb.append(NEWLINE);

			if (parameters != null) {
				sb.append(INDENT);
				sb.append(MessageFormat.format(res.getString("SMIMECapability.Parameter"),
						HexUtil.getHexString(parameters.toASN1Primitive().getEncoded())));
				sb.append(NEWLINE);
			}
		}

		return sb.toString();
	}

	private String getBitString(byte[] octets) throws IOException {

		if (octets == null) {
			return "";
		}

		DERBitString derBitString = DERBitString.getInstance(ASN1Primitive.fromByteArray(octets));
		byte[] bitStringBytes = derBitString.getBytes();

		return new BigInteger(1, bitStringBytes).toString(2);
	}

	private String getVeriSignNonVerified(byte[] octets) throws IOException {

		/*
		    NonVerified ::= SET OF ATTRIBUTE
		 */

		StringBuilder sb = new StringBuilder();

		ASN1Set asn1Set = ASN1Set.getInstance(octets);
		for (ASN1Encodable attribute : asn1Set.toArray()) {

			ASN1ObjectIdentifier attributeId = ((Attribute) attribute).getAttrType();
			ASN1Set attributeValues = ((Attribute) attribute).getAttrValues();

			for (ASN1Encodable attributeValue : attributeValues.toArray()) {

				String attributeValueStr = getAttributeValueString(attributeId, attributeValue);

				sb.append(MessageFormat.format("{0}={1}", attributeId.getId(), attributeValueStr));
				sb.append(NEWLINE);
			}
		}

		return sb.toString();
	}
}
