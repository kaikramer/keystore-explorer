/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2014 Kai Kramer
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
package net.sf.keystore_explorer.crypto.x509;

import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.COMMON_NAME;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.COUNTRY_NAME;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.DOMAIN_COMPONENT;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.EMAIL_ADDRESS;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.LOCALITY_NAME;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.MAIL;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.ORGANIZATIONAL_UNIT;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.ORGANIZATION_NAME;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.SERIAL_NUMBER;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.STATE_NAME;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.STREET_ADDRESS;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.TITLE;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.UNSTRUCTURED_ADDRESS;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.UNSTRUCTURED_NAME;
import static net.sf.keystore_explorer.crypto.x509.AttributeTypeType.USER_ID;
import static net.sf.keystore_explorer.crypto.x509.CertificatePolicyQualifierType.PKIX_CPS_POINTER_QUALIFIER;
import static net.sf.keystore_explorer.crypto.x509.CertificatePolicyQualifierType.PKIX_USER_NOTICE_QUALIFIER;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.AUTHORITY_INFORMATION_ACCESS;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.AUTHORITY_KEY_IDENTIFIER;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.BASIC_CONSTRAINTS;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.CERTIFICATE_ISSUER;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.CERTIFICATE_POLICIES;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.CRL_DISTRIBUTION_POINTS;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.CRL_NUMBER;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.DELTA_CRL_INDICATOR;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.ENTRUST_VERSION_INFORMATION;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.EXTENDED_KEY_USAGE;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.FRESHEST_CRL;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.HOLD_INSTRUCTION_CODE;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.INHIBIT_ANY_POLICY;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.INVALIDITY_DATE;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.ISSUER_ALTERNATIVE_NAME;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.ISSUING_DISTRIBUTION_POINT;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.KEY_USAGE;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.NAME_CONSTRAINTS;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.NETSCAPE_BASE_URL;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.NETSCAPE_CA_POLICY_URL;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.NETSCAPE_CA_REVOCATION_URL;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.NETSCAPE_CERTIFICATE_RENEWAL_URL;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.NETSCAPE_CERTIFICATE_TYPE;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.NETSCAPE_COMMENT;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.NETSCAPE_REVOCATION_URL;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.NETSCAPE_SSL_SERVER_NAME;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.POLICY_CONSTRAINTS;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.POLICY_MAPPINGS;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.PRIVATE_KEY_USAGE_PERIOD;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.REASON_CODE;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.SUBJECT_ALTERNATIVE_NAME;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.SUBJECT_DIRECTORY_ATTRIBUTES;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.SUBJECT_INFORMATION_ACCESS;
import static net.sf.keystore_explorer.crypto.x509.X509ExtensionType.SUBJECT_KEY_IDENTIFIER;

import java.io.IOException;
import java.math.BigInteger;
import java.text.MessageFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.ResourceBundle;

import net.sf.keystore_explorer.utilities.io.HexUtil;
import net.sf.keystore_explorer.utilities.io.IndentChar;
import net.sf.keystore_explorer.utilities.io.IndentSequence;
import net.sf.keystore_explorer.utilities.oid.ObjectIdUtil;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.AccessDescription;
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

/**
 * Holds the information of an X.509 extension and provides the ability to get
 * the extension's name and value as a string.
 *
 */
public class X509Ext {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/crypto/x509/resources");

	private String name;
	private ASN1ObjectIdentifier oid;
	private byte[] value;
	private boolean critical;

	private static final IndentSequence INDENT = new IndentSequence(IndentChar.SPACE, 4);
	private static final String NEWLINE = "\n";

	/**
	 * Construct a new immutable X509Ext.
	 *
	 * @param oid
	 *            X509Extension object identifier
	 * @param value
	 *            X509Extension value as a DER-encoded OCTET string
	 * @param critical
	 *            Critical extension?
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
	 * @param oid
	 *            X509Extension object identifier
	 * @param value
	 *            X509Extension value as a DER-encoded OCTET string
	 * @param critical
	 *            Critical extension?
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

		return new String(name);
	}

	/**
	 * Get extension value as a string.
	 *
	 * @return X509Extension value as a string
	 * @throws IOException
	 *             If an ASN.1 coding problem occurs
	 * @throws IOException
	 *             If an I/O problem occurs
	 */
	public String getStringValue() throws IOException, IOException {

		// Convert value from DER encoded octet string value to binary DER encoding
		ASN1OctetString octetString = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(value));
		byte[] octets = octetString.getOctets();

		X509ExtensionType type = X509ExtensionType.resolveOid(oid.getId());

		if (type == ENTRUST_VERSION_INFORMATION) {
			return getEntrustVersionInformationStringValue(octets);
		} else if (type == AUTHORITY_INFORMATION_ACCESS) {
			return getAuthorityInformationAccessStringValue(octets);
		} else if (type == SUBJECT_INFORMATION_ACCESS) {
			return getSubjectInformationAccessStringValue(octets);
		} else if (type == SUBJECT_DIRECTORY_ATTRIBUTES) {
			return getSubjectDirectoryAttributesStringValue(octets);
		} else if (type == SUBJECT_KEY_IDENTIFIER) {
			return getSubjectKeyIndentifierStringValue(octets);
		} else if (type == KEY_USAGE) {
			return getKeyUsageStringValue(octets);
		} else if (type == PRIVATE_KEY_USAGE_PERIOD) {
			return getPrivateKeyUsagePeriodStringValue(octets);
		} else if (type == SUBJECT_ALTERNATIVE_NAME) {
			return getSubjectAlternativeNameStringValue(octets);
		} else if (type == ISSUER_ALTERNATIVE_NAME) {
			return getIssuerAlternativeNameStringValue(octets);
		} else if (type == BASIC_CONSTRAINTS) {
			return getBasicConstraintsStringValue(octets);
		} else if (type == CRL_NUMBER) {
			return getCrlNumberStringValue(octets);
		} else if (type == REASON_CODE) {
			return getReasonCodeStringValue(octets);
		} else if (type == HOLD_INSTRUCTION_CODE) {
			return getHoldInstructionCodeStringValue(octets);
		} else if (type == INVALIDITY_DATE) {
			return getInvalidityDateStringValue(octets);
		} else if (type == DELTA_CRL_INDICATOR) {
			return getDeltaCrlIndicatorStringValue(octets);
		} else if (type == ISSUING_DISTRIBUTION_POINT) {
			return getIssuingDistributionPointStringValue(octets);
		} else if (type == CERTIFICATE_ISSUER) {
			return getCertificateIssuerStringValue(octets);
		} else if (type == NAME_CONSTRAINTS) {
			return getNameConstraintsStringValue(octets);
		} else if (type == CRL_DISTRIBUTION_POINTS) {
			return getCrlDistributionPointsStringValue(octets);
		} else if (type == CERTIFICATE_POLICIES) {
			return getCertificatePoliciesStringValue(octets);
		} else if (type == POLICY_MAPPINGS) {
			return getPolicyMappingsStringValue(octets);
		} else if (type == AUTHORITY_KEY_IDENTIFIER) {
			return getAuthorityKeyIdentifierStringValue(octets);
		} else if (type == POLICY_CONSTRAINTS) {
			return getPolicyConstraintsStringValue(octets);
		} else if (type == EXTENDED_KEY_USAGE) {
			return getExtendedKeyUsageStringValue(octets);
		} else if (type == FRESHEST_CRL) {
			return getFreshestCrlStringValue(octets);
		} else if (type == INHIBIT_ANY_POLICY) {
			return getInhibitAnyPolicyStringValue(octets);
		} else if (type == NETSCAPE_CERTIFICATE_TYPE) {
			return getNetscapeCertificateTypeStringValue(octets);
		} else if (type == NETSCAPE_BASE_URL) {
			return getNetscapeBaseUrlStringValue(octets);
		} else if (type == NETSCAPE_REVOCATION_URL) {
			return getNetscapeRevocationUrlStringValue(octets);
		} else if (type == NETSCAPE_CA_REVOCATION_URL) {
			return getNetscapeCaRevocationUrlStringValue(octets);
		} else if (type == NETSCAPE_CERTIFICATE_RENEWAL_URL) {
			return getNetscapeCertificateRenewalStringValue(octets);
		} else if (type == NETSCAPE_CA_POLICY_URL) {
			return getNetscapeCaPolicyUrlStringValue(octets);
		} else if (type == NETSCAPE_SSL_SERVER_NAME) {
			return getNetscapeSslServerNameStringValue(octets);
		} else if (type == NETSCAPE_COMMENT) {
			return getNetscapeCommentStringValue(octets);
		} else {
			/*
			 * X509Extension not recognised or means to output it not defined - just
			 * dump out hex and clear text
			 */
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

		StringBuffer strBuff = new StringBuffer();

		ASN1Sequence entrustVersInfo = (ASN1Sequence) ASN1Primitive.fromByteArray(value);

		DERGeneralString entrustVers = (DERGeneralString) entrustVersInfo.getObjectAt(0);
		DERBitString entrustInfoFlags = (DERBitString) entrustVersInfo.getObjectAt(1);

		strBuff.append(MessageFormat.format(res.getString("EntrustVersion"), entrustVers.getString()));
		strBuff.append(NEWLINE);
		strBuff.append(MessageFormat.format(res.getString("EntrustInformationFlags"), entrustInfoFlags.getString()));
		strBuff.append(NEWLINE);

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

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
			}
			// Unrecognised Access Method OID
			else {
				accessMethodStr = ObjectIdUtil.toString(accessMethod);
			}

			GeneralName accessLocation = accessDescription.getAccessLocation();

			String accessLocationStr = GeneralNameUtil.toString(accessLocation);

			strBuff.append(MessageFormat.format(res.getString("AuthorityInformationAccess"), accessDesc));
			strBuff.append(NEWLINE);
			strBuff.append(INDENT);
			strBuff.append(MessageFormat.format(res.getString("AccessMethod"), accessMethodStr));
			strBuff.append(NEWLINE);
			strBuff.append(INDENT);
			strBuff.append(res.getString("AccessLocation"));
			strBuff.append(NEWLINE);
			strBuff.append(INDENT);
			strBuff.append(INDENT);
			strBuff.append(accessLocationStr);
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

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

			strBuff.append(MessageFormat.format(res.getString("SubjectInformationAccess"), accessDesc));
			strBuff.append(NEWLINE);
			strBuff.append(INDENT);
			strBuff.append(MessageFormat.format(res.getString("AccessMethod"), accessMethodStr));
			strBuff.append(NEWLINE);
			strBuff.append(INDENT);
			strBuff.append(res.getString("AccessLocation"));
			strBuff.append(NEWLINE);
			strBuff.append(INDENT);
			strBuff.append(INDENT);
			strBuff.append(accessLocationStr);
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
	}

	private String getSubjectDirectoryAttributesStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * SubjectDirectoryAttributes ::= ASN1Sequence SIZE (1..MAX) OF
		 * Attribute
		 *
		 * Attribute ::= ASN1Sequence { type AttributeType, values SET OF
		 * AttributeValue }
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(value);

		for (Object attribute : subjectDirectoryAttributes.getAttributes()) {

			ASN1ObjectIdentifier attributeType = ((Attribute) attribute).getAttrType();
			String attributeTypeStr = attributeType.getId();

			ASN1Set attributeValues = ((Attribute) attribute).getAttrValues();

			for (Enumeration en = attributeValues.getObjects(); en.hasMoreElements();) {

				ASN1Encodable attributeValue = (ASN1Encodable) en.nextElement();

				String attributeValueStr = getAttributeValueString(attributeType, attributeValue);

				strBuff.append(MessageFormat.format("{0}={1}", attributeTypeStr, attributeValueStr));
				strBuff.append(NEWLINE);
			}
		}

		return strBuff.toString();
	}

	private String getSubjectKeyIndentifierStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * SubjectKeyIdentifier ::= KeyIdentifier
		 *
		 * KeyIdentifier ::= OCTET STRING
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(value);

		// Get key identifier from octet string
		byte[] keyIdentifierBytes = subjectKeyIdentifier.getKeyIdentifier();

		strBuff.append(MessageFormat.format(res.getString("SubjectKeyIdentifier"),
				HexUtil.getHexString(keyIdentifierBytes)));
		strBuff.append(NEWLINE);

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

		if (hasKeyUsage(keyUsages, KeyUsage.digitalSignature)) {
			strBuff.append(res.getString("DigitalSignatureKeyUsage"));
			strBuff.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.nonRepudiation)) {
			strBuff.append(res.getString("NonRepudiationKeyUsage"));
			strBuff.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.keyEncipherment)) {
			strBuff.append(res.getString("KeyEnciphermentKeyUsage"));
			strBuff.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.dataEncipherment)) {
			strBuff.append(res.getString("DataEnciphermentKeyUsage"));
			strBuff.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.keyAgreement)) {
			strBuff.append(res.getString("KeyAgreementKeyUsage"));
			strBuff.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.keyCertSign)) {
			strBuff.append(res.getString("KeyCertSignKeyUsage"));
			strBuff.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.cRLSign)) {
			strBuff.append(res.getString("CrlSignKeyUsage"));
			strBuff.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.encipherOnly)) {
			strBuff.append(res.getString("EncipherOnlyKeyUsage"));
			strBuff.append(NEWLINE);
		}
		if (hasKeyUsage(keyUsages, KeyUsage.decipherOnly)) {
			strBuff.append(res.getString("DecipherOnlyKeyUsage"));
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
	}

	private boolean hasKeyUsage(int keyUsages, int keyUsage) {
		return ((keyUsages & keyUsage) == keyUsage);
	}

	private String getPrivateKeyUsagePeriodStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * PrivateKeyUsagePeriod ::= ASN1Sequence { notBefore [0]
		 * ASN1GeneralizedTime OPTIONAL, notAfter [1] ASN1GeneralizedTime OPTIONAL }
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		PrivateKeyUsagePeriod privateKeyUsagePeriod = PrivateKeyUsagePeriod.getInstance(value);

		DERGeneralizedTime notBefore = privateKeyUsagePeriod.getNotBefore();
		DERGeneralizedTime notAfter = privateKeyUsagePeriod.getNotAfter();

		if (notBefore != null) {
			strBuff.append(MessageFormat.format(res.getString("NotBeforePrivateKeyUsagePeriod"),
					getGeneralizedTimeString(notBefore)));
		} else {
			strBuff.append(MessageFormat.format(res.getString("NotBeforePrivateKeyUsagePeriod"),
					res.getString("NoValue")));
		}
		strBuff.append(NEWLINE);

		if (notAfter != null) {
			strBuff.append(MessageFormat.format(res.getString("NotAfterPrivateKeyUsagePeriod"),
					getGeneralizedTimeString(notAfter)));
		} else {
			strBuff.append(MessageFormat.format(res.getString("NotAfterPrivateKeyUsagePeriod"),
					res.getString("NoValue")));
		}
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getSubjectAlternativeNameStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * SubjectAltName ::= GeneralNames
		 *
		 * GeneralNames ::= ASN1Sequence SIZE (1..MAX) OF GeneralName
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		GeneralNames subjectAltName = GeneralNames.getInstance(value);

		for (GeneralName generalName : subjectAltName.getNames()) {
			strBuff.append(GeneralNameUtil.toString(generalName));
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
	}

	private String getIssuerAlternativeNameStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * IssuerAltName ::= GeneralNames
		 *
		 * GeneralNames ::= ASN1Sequence SIZE (1..MAX) OF GeneralName
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		GeneralNames issuerAltName = GeneralNames.getInstance(value);

		for (GeneralName generalName : issuerAltName.getNames()) {
			strBuff.append(GeneralNameUtil.toString(generalName));
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

		BasicConstraints basicConstraints = BasicConstraints.getInstance(value);

		boolean ca = basicConstraints.isCA();
		BigInteger pathLenConstraint = basicConstraints.getPathLenConstraint();

		if (ca) {
			strBuff.append(res.getString("SubjectIsCa"));
			strBuff.append(NEWLINE);
		} else {
			strBuff.append(res.getString("SubjectIsNotCa"));
			strBuff.append(NEWLINE);
		}

		if (pathLenConstraint != null) {
			strBuff.append(MessageFormat.format(res.getString("PathLengthConstraint"), pathLenConstraint
					.intValue()));
			strBuff.append(NEWLINE);
		} else {
			strBuff.append(res.getString("NoPathLengthConstraint"));
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
	}

	private String getCrlNumberStringValue(byte[] value) throws IOException {
		// @formatter:off
		/* CRLNumber ::= ASN1Integer (0..MAX) */
		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		CRLNumber crlNumber = CRLNumber.getInstance(value);

		strBuff.append(HexUtil.getHexString(crlNumber.getCRLNumber()));
		strBuff.append(NEWLINE);

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

		CRLReason crlReason = CRLReason.getInstance(value);

		long crlReasonLong = crlReason.getValue().longValue();

		if (crlReasonLong == CRLReason.unspecified) {
			strBuff.append(res.getString("UnspecifiedCrlReason"));
		} else if (crlReasonLong == CRLReason.keyCompromise) {
			strBuff.append(res.getString("KeyCompromiseCrlReason"));
		} else if (crlReasonLong == CRLReason.cACompromise) {
			strBuff.append(res.getString("CaCompromiseCrlReason"));
		} else if (crlReasonLong == CRLReason.affiliationChanged) {
			strBuff.append(res.getString("AffiliationChangedCrlReason"));
		} else if (crlReasonLong == CRLReason.superseded) {
			strBuff.append(res.getString("SupersededCrlReason"));
		} else if (crlReasonLong == CRLReason.cessationOfOperation) {
			strBuff.append(res.getString("CessationOfOperationCrlReason"));
		} else if (crlReasonLong == CRLReason.certificateHold) {
			strBuff.append(res.getString("CertificateHoldCrlReason"));
		} else if (crlReasonLong == CRLReason.removeFromCRL) {
			strBuff.append(res.getString("RemoveFromCrlCrlReason"));
		} else if (crlReasonLong == CRLReason.privilegeWithdrawn) {
			strBuff.append(res.getString("PrivilegeWithdrawnCrlReason"));
		} else
		// CRLReason.aACompromise
		{
			strBuff.append(res.getString("AaCompromiseCrlReason"));
		}

		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getHoldInstructionCodeStringValue(byte[] value) throws IOException {
		// @formatter:off
		/* HoldInstructionCode ::= OBJECT IDENTIFER */
		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		ASN1ObjectIdentifier holdInstructionCode = ASN1ObjectIdentifier.getInstance(value);
		HoldInstructionCodeType holdInstructionCodeType =
				HoldInstructionCodeType.resolveOid(holdInstructionCode.getId());

		if (holdInstructionCodeType != null) {
			strBuff.append(holdInstructionCodeType.friendly());
		} else {
			// Unrecognised Hold Instruction Code
			strBuff.append(holdInstructionCode.getId());
		}
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getInvalidityDateStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* InvalidityDate ::= ASN1GeneralizedTime */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		DERGeneralizedTime invalidityDate = DERGeneralizedTime.getInstance(value);

		strBuff.append(getGeneralizedTimeString(invalidityDate));
		strBuff.append(NEWLINE);

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();
		strBuff.append(HexUtil.getHexString(crlNum));
		strBuff.append(NEWLINE);

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

		IssuingDistributionPoint issuingDistributionPoint = IssuingDistributionPoint.getInstance(value);

		DistributionPointName distributionPointName = issuingDistributionPoint.getDistributionPoint();

		if (distributionPointName != null) { // Optional
			strBuff.append(getDistributionPointNameString(distributionPointName, ""));
		}

		boolean onlyContainsUserCerts = issuingDistributionPoint.onlyContainsUserCerts();
		strBuff.append(MessageFormat.format(res.getString("OnlyContainsUserCerts"), onlyContainsUserCerts));
		strBuff.append(NEWLINE);

		boolean onlyContainsCaCerts = issuingDistributionPoint.onlyContainsCACerts();
		strBuff.append(MessageFormat.format(res.getString("OnlyContainsCaCerts"), onlyContainsCaCerts));
		strBuff.append(NEWLINE);

		ReasonFlags onlySomeReasons = issuingDistributionPoint.getOnlySomeReasons();
		if (onlySomeReasons != null) {// Optional
			strBuff.append(res.getString("OnlySomeReasons"));
			strBuff.append(NEWLINE);

			String[] reasonFlags = getReasonFlagsStrings(onlySomeReasons);

			for (String reasonFlag : reasonFlags) {
				strBuff.append(INDENT);
				strBuff.append(reasonFlag);
				strBuff.append(NEWLINE);
			}
		}

		boolean indirectCrl = issuingDistributionPoint.isIndirectCRL();
		strBuff.append(MessageFormat.format(res.getString("IndirectCrl"), indirectCrl));
		strBuff.append(NEWLINE);

		boolean onlyContainsAttributeCerts = issuingDistributionPoint.onlyContainsAttributeCerts();
		strBuff.append(MessageFormat.format(res.getString("OnlyContainsAttributeCerts"), onlyContainsAttributeCerts));
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getCertificateIssuerStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * certificateIssuer ::= GeneralNames
		 *
		 * GeneralNames ::= ASN1Sequence SIZE (1..MAX) OF GeneralName
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		GeneralNames certificateIssuer = GeneralNames.getInstance(value);

		for (GeneralName generalName : certificateIssuer.getNames()) {
			strBuff.append(GeneralNameUtil.toString(generalName));
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

		NameConstraints nameConstraints = NameConstraints.getInstance(value);

		GeneralSubtrees permittedSubtrees = null;
		if ((nameConstraints.getPermittedSubtrees() != null) &&
				(nameConstraints.getPermittedSubtrees().length != 0)) {
			permittedSubtrees = new GeneralSubtrees(nameConstraints.getPermittedSubtrees());
		}

		strBuff.append(res.getString("PermittedSubtrees"));

		if (permittedSubtrees == null) {
			strBuff.append(" " + res.getString("NoValue"));
			strBuff.append(NEWLINE);
		} else {
			strBuff.append(NEWLINE);

			int permitted = 0;

			for (GeneralSubtree permittedSubtree : permittedSubtrees.getGeneralSubtrees()) {
				permitted++;

				strBuff.append(INDENT);
				strBuff.append(MessageFormat.format(res.getString("PermittedSubtree"), permitted));
				strBuff.append(NEWLINE);

				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(res.getString("Base"));
				strBuff.append(NEWLINE);

				GeneralName base = permittedSubtree.getBase();

				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(GeneralNameUtil.toString(base));
				strBuff.append(NEWLINE);

				BigInteger minimum = permittedSubtree.getMinimum();
				int minimumInt = 0; // Default 'nodistance' value

				if (minimum != null) {
					minimumInt = minimum.intValue();
				}

				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(MessageFormat.format(res.getString("Minimum"), minimumInt));
				strBuff.append(NEWLINE);

				BigInteger maximum = permittedSubtree.getMaximum();

				if (maximum != null) {
					int maximumInt = maximum.intValue();

					strBuff.append(INDENT);
					strBuff.append(INDENT);
					strBuff.append(MessageFormat.format(res.getString("Minimum"), maximumInt));
					strBuff.append(NEWLINE);
				}
			}
		}

		GeneralSubtrees excludedSubtrees = new GeneralSubtrees(nameConstraints.getExcludedSubtrees());

		strBuff.append(res.getString("ExcludedSubtrees"));

		if (excludedSubtrees == null) // Optional
		{
			strBuff.append(" " + res.getString("NoValue"));
			strBuff.append(NEWLINE);
		} else {
			strBuff.append(NEWLINE);

			int excluded = 0;

			for (GeneralSubtree excludedSubtree : excludedSubtrees.getGeneralSubtrees()) {
				excluded++;

				strBuff.append(INDENT);
				strBuff.append(MessageFormat.format(res.getString("ExcludedSubtree"), excluded));
				strBuff.append(NEWLINE);

				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(res.getString("Base"));
				strBuff.append(NEWLINE);

				GeneralName base = excludedSubtree.getBase();

				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(GeneralNameUtil.toString(base));
				strBuff.append(NEWLINE);

				BigInteger minimum = excludedSubtree.getMinimum();
				int minimumInt = minimum.intValue();

				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(MessageFormat.format(res.getString("Minimum"), minimumInt));
				strBuff.append(NEWLINE);

				BigInteger maximum = excludedSubtree.getMaximum();
				int maximumInt = maximum.intValue();

				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(MessageFormat.format(res.getString("Maximum"), maximumInt));
				strBuff.append(NEWLINE);
			}
		}

		return strBuff.toString();
	}

	private String getCrlDistributionPointsStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * CRLDistPointSyntax ::= ASN1Sequence SIZE (1..MAX) OF
		 * DistributionPoint
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		CRLDistPoint crlDistributionPoints = CRLDistPoint.getInstance(value);

		int distPoint = 0;

		for (DistributionPoint distributionPoint : crlDistributionPoints.getDistributionPoints()) {
			distPoint++;

			strBuff.append(MessageFormat.format(res.getString("CrlDistributionPoint"), distPoint));
			strBuff.append(NEWLINE);

			strBuff.append(getDistributionPointString(distributionPoint, INDENT.toString(1)));
		}

		return strBuff.toString();
	}

	private String getCertificatePoliciesStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * CertificatePolicies ::= ASN1Sequence SIZE (1..MAX) OF
		 * PolicyInformation
		 *
		 * PolicyInformation ::= ASN1Sequence { policyIdentifier CertPolicyId,
		 * policyQualifiers ASN1Sequence SIZE (1..MAX) OF PolicyQualifierInfo
		 * OPTIONAL }
		 *
		 * CertPolicyId ::= OBJECT IDENTIFIER
		 *
		 * PolicyQualifierInfo ::= ASN1Sequence { policyQualifierId
		 * PolicyQualifierId, qualifier ANY DEFINED BY policyQualifierId }
		 *
		 * PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
		 *
		 * Qualifier ::= CHOICE { cPSuri CPSuri, userNotice UserNotice }
		 *
		 * CPSuri ::= DERIA5String
		 *
		 * UserNotice ::= ASN1Sequence { noticeRef NoticeReference OPTIONAL,
		 * explicitText DisplayText OPTIONAL }
		 *
		 * NoticeReference ::= ASN1Sequence { organization DisplayText,
		 * noticeNumbers ASN1Sequence OF ASN1Integer }
		 *
		 * DisplayText ::= CHOICE { ia5String DERIA5String (SIZE (1..200)),
		 * visibleString VisibleString (SIZE (1..200)), bmpString BMPString
		 * (SIZE (1..200)), utf8String UTF8String (SIZE (1..200)) }
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);

		int certPolicy = 0;

		for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
			certPolicy++;

			strBuff.append(MessageFormat.format(res.getString("CertificatePolicy"), certPolicy));
			strBuff.append(NEWLINE);

			ASN1ObjectIdentifier policyIdentifier = policyInformation.getPolicyIdentifier();
			String policyIdentifierStr = ObjectIdUtil.toString(policyIdentifier);

			strBuff.append(INDENT);
			strBuff.append(MessageFormat.format(res.getString("PolicyIdentifier"), policyIdentifierStr));
			strBuff.append(NEWLINE);

			ASN1Sequence policyQualifiers = policyInformation.getPolicyQualifiers();

			if (policyQualifiers != null) { // Optional
				int policyQual = 0;

				for (Enumeration en = policyQualifiers.getObjects();  en.hasMoreElements();) {

					ASN1Sequence policyQualifierInfo = (ASN1Sequence)  en.nextElement();

					policyQual++;

					strBuff.append(INDENT);
					strBuff.append(INDENT);
					strBuff.append(MessageFormat.format(res.getString("PolicyQualifierInformation"), certPolicy,
							policyQual));
					strBuff.append(NEWLINE);

					ASN1ObjectIdentifier policyQualifierId = (ASN1ObjectIdentifier) policyQualifierInfo.getObjectAt(0);

					CertificatePolicyQualifierType certificatePolicyQualifierType = CertificatePolicyQualifierType
							.resolveOid(policyQualifierId.getId());

					if (certificatePolicyQualifierType != null) {
						strBuff.append(INDENT);
						strBuff.append(INDENT);
						strBuff.append(INDENT);
						strBuff.append(certificatePolicyQualifierType.friendly());
						strBuff.append(NEWLINE);

						if (certificatePolicyQualifierType == PKIX_CPS_POINTER_QUALIFIER) {
							DERIA5String cpsPointer = (DERIA5String) policyQualifierInfo.getObjectAt(1);

							strBuff.append(INDENT);
							strBuff.append(INDENT);
							strBuff.append(INDENT);
							strBuff.append(MessageFormat.format(res.getString("CpsPointer"), cpsPointer));
							strBuff.append(NEWLINE);
						} else if (certificatePolicyQualifierType == PKIX_USER_NOTICE_QUALIFIER) {
							ASN1Encodable userNoticeObj = policyQualifierInfo.getObjectAt(1);

							UserNotice userNotice = UserNotice.getInstance(userNoticeObj);

							strBuff.append(INDENT);
							strBuff.append(INDENT);
							strBuff.append(INDENT);
							strBuff.append(res.getString("UserNotice"));
							strBuff.append(NEWLINE);

							NoticeReference noticeReference = userNotice.getNoticeRef();

							DisplayText explicitText = userNotice.getExplicitText();

							if (noticeReference != null) { // Optional
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(res.getString("NoticeReference"));
								strBuff.append(NEWLINE);

								DisplayText organization = noticeReference.getOrganization();

								String organizationString = organization.getString();

								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(MessageFormat.format(res.getString("Organization"), organizationString));
								strBuff.append(NEWLINE);

								ASN1Integer[] noticeNumbers = noticeReference.getNoticeNumbers();

								StringBuffer sbNoticeNumbers = new StringBuffer();
								for (ASN1Integer noticeNumber : noticeNumbers) {
									sbNoticeNumbers.append(noticeNumber.getValue().intValue());
									sbNoticeNumbers.append(", ");
								}
								sbNoticeNumbers.setLength(sbNoticeNumbers.length() - 2);

								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(MessageFormat.format(res.getString("NoticeNumbers"),
										sbNoticeNumbers.toString()));
								strBuff.append(NEWLINE);
							}

							if (explicitText != null) // Optional
							{
								String explicitTextString = explicitText.getString();

								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(INDENT);
								strBuff.append(MessageFormat.format(res.getString("ExplicitText"), explicitTextString));
								strBuff.append(NEWLINE);
							}
						}
					}
				}
			}
		}

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

		PolicyMappings policyMappings = PolicyMappings.getInstance(value);
		ASN1Sequence policyMappingsSeq = (ASN1Sequence) policyMappings.toASN1Primitive();

		int polMap = 0;

		for (ASN1Encodable policyMapping : policyMappingsSeq.toArray()) {

			ASN1Sequence policyMappingSeq = ASN1Sequence.getInstance(policyMapping.toASN1Primitive());
			polMap++;

			strBuff.append(MessageFormat.format(res.getString("PolicyMapping"), polMap));
			strBuff.append(NEWLINE);

			ASN1ObjectIdentifier issuerDomainPolicy = (ASN1ObjectIdentifier) policyMappingSeq.getObjectAt(0);
			ASN1ObjectIdentifier subjectDomainPolicy = (ASN1ObjectIdentifier) policyMappingSeq.getObjectAt(1);

			strBuff.append(INDENT);
			strBuff.append(MessageFormat.format(res.getString("IssuerDomainPolicy"),
					ObjectIdUtil.toString(issuerDomainPolicy)));
			strBuff.append(NEWLINE);

			strBuff.append(INDENT);
			strBuff.append(MessageFormat.format(res.getString("SubjectDomainPolicy"),
					ObjectIdUtil.toString(subjectDomainPolicy)));
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

		AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(value);

		byte[] keyIdentifier = authorityKeyIdentifier.getKeyIdentifier();
		GeneralNames authorityCertIssuer = authorityKeyIdentifier.getAuthorityCertIssuer();
		BigInteger certificateSerialNumber = authorityKeyIdentifier.getAuthorityCertSerialNumber();

		if (keyIdentifier != null) { // Optional
			// Output as a hex string
			strBuff.append(MessageFormat.format(res.getString("AuthorityKeyIdentifier"),
					HexUtil.getHexString(keyIdentifier)));
			strBuff.append(NEWLINE);
		}

		if (authorityCertIssuer != null) { // Optional
			strBuff.append(res.getString("CertificateIssuer"));
			strBuff.append(NEWLINE);

			for (GeneralName generalName : authorityCertIssuer.getNames()) {
				strBuff.append(INDENT);
				strBuff.append(GeneralNameUtil.toString(generalName));
				strBuff.append(NEWLINE);
			}
		}

		if (certificateSerialNumber != null) { // Optional
			// Output as an integer
			strBuff.append(MessageFormat.format(res.getString("CertificateSerialNumber"),
					HexUtil.getHexString(certificateSerialNumber)));
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

		PolicyConstraints policyConstraints = PolicyConstraints.getInstance(value);

		int requireExplicitPolicy = policyConstraints.getRequireExplicitPolicy();
		int inhibitPolicyMapping = policyConstraints.getInhibitPolicyMapping();

		if (requireExplicitPolicy != -1) { // Optional
			strBuff.append(MessageFormat.format(res.getString("RequireExplicitPolicy"), requireExplicitPolicy));
			strBuff.append(NEWLINE);
		}

		if (inhibitPolicyMapping != -1) { // Optional
			strBuff.append(MessageFormat.format(res.getString("InhibitPolicyMapping"), inhibitPolicyMapping));
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
	}

	private String getExtendedKeyUsageStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * ExtendedKeyUsage ::= ASN1Sequence SIZE (1..MAX) OF KeyPurposeId
		 *
		 * KeyPurposeId ::= OBJECT IDENTIFIER
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(value);

		for (KeyPurposeId keyPurposeId : extendedKeyUsage.getUsages()) {
			String oid = keyPurposeId.getId();

			ExtendedKeyUsageType type = ExtendedKeyUsageType.resolveOid(oid);

			if (type != null) {
				strBuff.append(type.friendly());
			} else {
				// Unrecognised key purpose ID
				strBuff.append(oid);
			}

			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
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

		StringBuffer strBuff = new StringBuffer();

		CRLDistributionPoints freshestCRL = CRLDistributionPoints.getInstance(value);

		int distPoint = 0;

		for (DistributionPoint distributionPoint : freshestCRL.getDistributionPointList()) {
			distPoint++;

			strBuff.append(MessageFormat.format(res.getString("FreshestCrlDistributionPoint"), distPoint));
			strBuff.append(NEWLINE);

			strBuff.append(getDistributionPointString(distributionPoint, INDENT.toString(1)));
		}

		return strBuff.toString();
	}

	private String getInhibitAnyPolicyStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * InhibitAnyPolicy ::= SkipCerts
		 *
		 * SkipCerts ::= ASN1Integer (0..MAX)
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		InhibitAnyPolicy inhibitAnyPolicy = InhibitAnyPolicy.getInstance(value);

		int skipCerts = inhibitAnyPolicy.getSkipCerts();

		strBuff.append(MessageFormat.format(res.getString("InhibitAnyPolicy"), skipCerts));
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getNetscapeCertificateTypeStringValue(byte[] value) throws IOException {
		// @formatter:off

		/*
		 * NetscapeCertType ::= BIT STRING { sslClient (0), sslServer (1), smime
		 * (2), objectSigning (3), reserved (4), sslCA (5), smimeCA (6),
		 * objectSigningCA (7) }
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		@SuppressWarnings("resource") // we have a ByteArrayInputStream here which does not need to be closed
		DERBitString netscapeCertType = NetscapeCertType.getInstance(new ASN1InputStream(value).readObject());

		int netscapeCertTypes = netscapeCertType.intValue();

		if (isCertType(netscapeCertTypes, NetscapeCertType.sslClient)) {
			strBuff.append(res.getString("SslClientNetscapeCertificateType"));
			strBuff.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.sslServer)) {
			strBuff.append(res.getString("SslServerNetscapeCertificateType"));
			strBuff.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.smime)) {
			strBuff.append(res.getString("SmimeNetscapeCertificateType"));
			strBuff.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.objectSigning)) {
			strBuff.append(res.getString("ObjectSigningNetscapeCertificateType"));
			strBuff.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.reserved)) {
			strBuff.append(res.getString("ReservedNetscapeCertificateType"));
			strBuff.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.sslCA)) {
			strBuff.append(res.getString("SslCaNetscapeCertificateType"));
			strBuff.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.smimeCA)) {
			strBuff.append(res.getString("SmimeCaNetscapeCertificateType"));
			strBuff.append(NEWLINE);
		}

		if (isCertType(netscapeCertTypes, NetscapeCertType.objectSigningCA)) {
			strBuff.append(res.getString("ObjectSigningCaNetscapeCertificateType"));
			strBuff.append(NEWLINE);
		}

		return strBuff.toString();
	}

	private boolean isCertType(int netscapeCertTypes, int certType) {
		return ((netscapeCertTypes & certType) == certType);
	}

	private String getNetscapeBaseUrlStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeBaseUrl ::= DERIA5String */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		DERIA5String netscapeBaseUrl = DERIA5String.getInstance(value);

		strBuff.append(netscapeBaseUrl.getString());
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getNetscapeRevocationUrlStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeRevocationUrl ::= DERIA5String */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		DERIA5String netscapeRevocationUrl = DERIA5String.getInstance(value);

		strBuff.append(netscapeRevocationUrl.getString());
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getNetscapeCaRevocationUrlStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeCARevocationUrl ::= DERIA5String */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		DERIA5String netscapeCaRevocationUrl = DERIA5String.getInstance(value);

		strBuff.append(netscapeCaRevocationUrl.getString());
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getNetscapeCertificateRenewalStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeCertRenewalUrl ::= DERIA5String */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		DERIA5String netscapeCertRenewalUrl = DERIA5String.getInstance(value);

		strBuff.append(netscapeCertRenewalUrl.getString());
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getNetscapeCaPolicyUrlStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeCAPolicyUrl ::= DERIA5String */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		DERIA5String netscapeCaPolicyUrl = DERIA5String.getInstance(value);

		strBuff.append(netscapeCaPolicyUrl.getString());
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getNetscapeSslServerNameStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeSslServerName ::= DERIA5String */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		DERIA5String netscapeSslServerName = DERIA5String.getInstance(value);

		strBuff.append(netscapeSslServerName.getString());
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getNetscapeCommentStringValue(byte[] value) throws IOException {
		// @formatter:off

		/* NetscapeComment ::= DERIA5String */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		DERIA5String netscapeComment = DERIA5String.getInstance(value);

		strBuff.append(netscapeComment.getString());
		strBuff.append(NEWLINE);

		return strBuff.toString();
	}

	private String getDistributionPointString(DistributionPoint distributionPoint, String baseIndent)
			throws IOException {
		// @formatter:off

		/*
		 * DistributionPoint ::= ASN1Sequence { distributionPoint [0]
		 * DistributionPointName OPTIONAL, reasons [1] ReasonFlags OPTIONAL,
		 * cRLIssuer [2] GeneralNames OPTIONAL }
		 *
		 * GeneralNames ::= ASN1Sequence SIZE (1..MAX) OF GeneralName
		 */

		// @formatter:on

		StringBuffer strBuff = new StringBuffer();

		DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
		ReasonFlags reasons = distributionPoint.getReasons();
		GeneralNames crlIssuer = distributionPoint.getCRLIssuer();

		if (distributionPointName != null) // Optional
		{
			strBuff.append(getDistributionPointNameString(distributionPointName, baseIndent));
		}

		if (reasons != null) // Optional
		{
			strBuff.append(baseIndent);
			strBuff.append(res.getString("DistributionPointReasons"));
			strBuff.append(NEWLINE);

			String[] reasonFlags = getReasonFlagsStrings(reasons);

			for (String reasonFlag : reasonFlags) {
				strBuff.append(baseIndent);
				strBuff.append(INDENT);
				strBuff.append(reasonFlag);
				strBuff.append(NEWLINE);
			}
		}

		if (crlIssuer != null) // Optional
		{
			strBuff.append(baseIndent);
			strBuff.append(res.getString("DistributionPointCrlIssuer"));
			strBuff.append(NEWLINE);

			for (GeneralName generalName : crlIssuer.getNames()) {
				strBuff.append(baseIndent);
				strBuff.append(INDENT);
				strBuff.append(GeneralNameUtil.toString(generalName));
				strBuff.append(NEWLINE);
			}
		}

		return strBuff.toString();
	}

	private String getDistributionPointNameString(DistributionPointName distributionPointName, String baseIndent)
			throws IOException {
		// @formatter:off

		/*
		 * DistributionPointName ::= CHOICE { fullname [0] GeneralNames,
		 * nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
		 *
		 * RelativeDistinguishedName ::= SET SIZE (1 .. MAX) OF
		 * AttributeTypeAndValue
		 *
		 * AttributeTypeAndValue ::= ASN1Sequence { type AttributeType, value
		 * AttributeValue }
		 */

		// @formatter: on

		StringBuffer strBuff = new StringBuffer();

		strBuff.append(baseIndent);
		strBuff.append(res.getString("DistributionPointName"));
		strBuff.append(NEWLINE);

		if (distributionPointName.getType() == DistributionPointName.FULL_NAME) {
			strBuff.append(baseIndent);
			strBuff.append(INDENT);
			strBuff.append(res.getString("DistributionPointFullName"));
			strBuff.append(NEWLINE);

			GeneralNames generalNames = GeneralNames.getInstance(distributionPointName.getName());

			for (GeneralName generalName : generalNames.getNames()) {
				strBuff.append(baseIndent);
				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(GeneralNameUtil.toString(generalName));
				strBuff.append(NEWLINE);
			}
		} else {
			// DistributionPointName.TAG_NAMERELATIVETOCRLISSUER
			strBuff.append(baseIndent);
			strBuff.append(INDENT);
			strBuff.append(res.getString("DistributionPointNameRelativeToCrlIssuer"));
			strBuff.append(NEWLINE);

			RDN rdn = RDN.getInstance(distributionPointName.getName());

			for (AttributeTypeAndValue attributeTypeAndValue : rdn.getTypesAndValues()) {
				ASN1ObjectIdentifier attributeType = attributeTypeAndValue.getType();
				ASN1Encodable attributeValue = attributeTypeAndValue.getValue();

				String attributeTypeStr = getAttributeTypeString(attributeType);
				String attributeValueStr = getAttributeValueString(attributeType, attributeValue);

				strBuff.append(baseIndent);
				strBuff.append(INDENT);
				strBuff.append(INDENT);
				strBuff.append(MessageFormat.format("{0}={1}", attributeTypeStr, attributeValueStr));
				strBuff.append(NEWLINE);
			}
		}

		return strBuff.toString();
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
		return ((reasonFlags & reasonFlag) == reasonFlag);
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
		// @formatter:off

		/* AttributeValue ::= ANY */

		// @formatter:on

		// Get value string for recognized attribute types
		AttributeTypeType attributeTypeType = AttributeTypeType.resolveOid(attributeType.getId());

		if (attributeTypeType == COMMON_NAME) {
			DirectoryString commonName = DirectoryString.getInstance(ASN1Primitive.fromByteArray(value));
			return commonName.getString();
		} else if (attributeTypeType == SERIAL_NUMBER) {
			DERPrintableString serialNumber = DERPrintableString.getInstance(value);
			return serialNumber.getString();
		} else if (attributeTypeType == COUNTRY_NAME) {
			DERPrintableString countryName = DERPrintableString.getInstance(value);
			return countryName.getString();
		} else if (attributeTypeType == LOCALITY_NAME) {
			DirectoryString localityName = DirectoryString.getInstance(ASN1Primitive.fromByteArray(value));
			return localityName.getString();
		} else if (attributeTypeType == STATE_NAME) {
			DirectoryString stateName = DirectoryString.getInstance(ASN1Primitive.fromByteArray(value));
			return stateName.getString();
		} else if (attributeTypeType == STREET_ADDRESS) {
			DirectoryString street = DirectoryString.getInstance(ASN1Primitive.fromByteArray(value));
			return street.getString();
		} else if (attributeTypeType == ORGANIZATION_NAME) {
			DirectoryString organizationName = DirectoryString.getInstance(ASN1Primitive.fromByteArray(value));
			return organizationName.getString();
		} else if (attributeTypeType == ORGANIZATIONAL_UNIT) {
			DirectoryString organizationalUnitName = DirectoryString.getInstance(ASN1Primitive.fromByteArray(value));
			return organizationalUnitName.getString();
		} else if (attributeTypeType == TITLE) {
			DirectoryString title = DirectoryString.getInstance(ASN1Primitive.fromByteArray(value));
			return title.getString();
		} else if (attributeTypeType == EMAIL_ADDRESS) {
			DERIA5String emailAddress = DERIA5String.getInstance(value);
			return emailAddress.getString();
		} else if (attributeTypeType == UNSTRUCTURED_NAME) {
			DERIA5String emailAddress = DERIA5String.getInstance(value);
			return emailAddress.getString();
		} else if (attributeTypeType == UNSTRUCTURED_ADDRESS) {
			DERPrintableString serialNumber = DERPrintableString.getInstance(value);
			return serialNumber.getString();
		} else if (attributeTypeType == USER_ID) {
			DirectoryString title = DirectoryString.getInstance(ASN1Primitive.fromByteArray(value));
			return title.getString();
		} else if (attributeTypeType == MAIL) {
			DERIA5String emailAddress = DERIA5String.getInstance(value);
			return emailAddress.getString();
		} else if (attributeTypeType == DOMAIN_COMPONENT) {
			DERIA5String domainComponent = DERIA5String.getInstance(value);
			return domainComponent.getString();
		}
		// Attribute type not recognized - return hex string for value
		else {
			return HexUtil.getHexString(value);
		}
	}

	private String getGeneralizedTimeString(DERGeneralizedTime notBefore) {
		// Get generalized time as a date
		Date date;
		try {
			date = notBefore.getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException("Cannot parse date");
		}

		// Format date
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MMM/yyyy HH:mm:ss.SSS z");

		return sdf.format(date);
	}
}
