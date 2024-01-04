/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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

import java.util.ResourceBundle;

/**
 * Enumeration of X.509 certificate extensions.
 */
public enum X509ExtensionType {

    // @formatter:off

	// ////////////////////////////////
	// Active X509Extension OIDs
	// ////////////////////////////////

	/** Entrust Version Information */
	ENTRUST_VERSION_INFORMATION("1.2.840.113533.7.65.0", "EntrustVersionInformationCertExt"),

	/** Authority Information Access */
	AUTHORITY_INFORMATION_ACCESS("1.3.6.1.5.5.7.1.1", "AuthorityInformationAccessCertExt"),

	/** Authority Information Access */
	SUBJECT_INFORMATION_ACCESS("1.3.6.1.5.5.7.1.11", "SubjectInformationAccessCertExt"),

	/** Subject Directory Attributes */
	SUBJECT_DIRECTORY_ATTRIBUTES("2.5.29.9", "SubjectDirectoryAttributesCertExt"),

	/** Subject Key Identifier */
	SUBJECT_KEY_IDENTIFIER("2.5.29.14", "SubjectKeyIdentifierCertExt"),

	/** Key Usage */
	KEY_USAGE("2.5.29.15", "KeyUsageCertExt"),

	/** Private Key Usage Period */
	PRIVATE_KEY_USAGE_PERIOD("2.5.29.16", "PrivateKeyUsagePeriodCertExt"),

	/** Subject Alternative Name */
	SUBJECT_ALTERNATIVE_NAME("2.5.29.17", "SubjectAlternativeNameCertExt"),

	/** Issuer Alternative Name */
	ISSUER_ALTERNATIVE_NAME("2.5.29.18", "IssuerAlternativeNameCertExt"),

	/** Basic Constraints */
	BASIC_CONSTRAINTS("2.5.29.19", "BasicConstraintsCertExt"),

	/** CRL Number */
	CRL_NUMBER("2.5.29.20", "CrlNumberCertExt"),

	/** Reason code */
	REASON_CODE("2.5.29.21", "ReasonCodeCertExt"),

	/** Hold Instruction Code */
	HOLD_INSTRUCTION_CODE("2.5.29.23", "HoldInstructionCodeCertExt"),

	/** Invalidity Date */
	INVALIDITY_DATE("2.5.29.24", "InvalidityDateCertExt"),

	/** Delta CRL Indicator */
	DELTA_CRL_INDICATOR("2.5.29.27", "DeltaCrlIndicatorCertExt"),

	/** Issuing Distribution Point */
	ISSUING_DISTRIBUTION_POINT("2.5.29.28", "IssuingDistributionPointCertExt"),

	/** Certificate Issuer */
	CERTIFICATE_ISSUER("2.5.29.29", "CertificateIssuerCertExt"),

	/** Name Constraints */
	NAME_CONSTRAINTS("2.5.29.30", "NameConstraintsCertExt"),

	/** CRL Distribution Points */
	CRL_DISTRIBUTION_POINTS("2.5.29.31", "CrlDistributionPointsCertExt"),

	/** Certificate Policies */
	CERTIFICATE_POLICIES("2.5.29.32", "CertificatePoliciesCertExt"),

	/** Policy Mappings */
	POLICY_MAPPINGS("2.5.29.33", "PolicyMappingsCertExt"),

	/** Authority Key Identifier */
	AUTHORITY_KEY_IDENTIFIER("2.5.29.35", "AuthorityKeyIdentifierCertExt"),

	/** Policy Constraints */
	POLICY_CONSTRAINTS("2.5.29.36", "PolicyConstraintsCertExt"),

	/** Extended Key Usage */
	EXTENDED_KEY_USAGE("2.5.29.37", "ExtendedKeyUsageCertExt"),

	/** Freshest CRL */
	FRESHEST_CRL("2.5.29.46", "FreshestCrlCertExt"),

	/** Inhibit Any Policy */
	INHIBIT_ANY_POLICY("2.5.29.54", "InhibitAnyPolicyCertExt"),

	// ////////////////////////////////
	// Netscape Extensions
	// ////////////////////////////////

	/** Netscape Certificate Type */
	NETSCAPE_CERTIFICATE_TYPE("2.16.840.1.113730.1.1", "NetscapeCertificateTypeCertExt"),

	/** Netscape Base URL */
	NETSCAPE_BASE_URL("2.16.840.1.113730.1.2", "NetscapeBaseUrlCertExt"),

	/** Netscape Revocation URL */
	NETSCAPE_REVOCATION_URL("2.16.840.1.113730.1.3", "NetscapeRevocationUrlCertExt"),

	/** Netscape CA Revocation URL */
	NETSCAPE_CA_REVOCATION_URL("2.16.840.1.113730.1.4", "NetscapeCaRevocationUrlCertExt"),

	/** Netscape Certificate Renewal URL */
	NETSCAPE_CERTIFICATE_RENEWAL_URL("2.16.840.1.113730.1.7", "NetscapeCertificateRenewalUrlCertExt"),

	/** Netscape CA Policy URL */
	NETSCAPE_CA_POLICY_URL("2.16.840.1.113730.1.8", "NetscapeCaPolicyUrlCertExt"),

	/** Netscape SSL Server Name */
	NETSCAPE_SSL_SERVER_NAME("2.16.840.1.113730.1.12", "NetscapeSslServerNameCertExt"),

	/** Netscape Comment */
	NETSCAPE_COMMENT("2.16.840.1.113730.1.13", "NetscapeCommentCertExt"),

	// ////////////////////////////////
	// Undocumented X509Extension OIDs
	// ////////////////////////////////

	/** Authority Attribute Identifier */
	AUTHORITY_ATTRIBUTE_IDENTIFIER("2.5.29.38", "AuthorityAttributeIdentifierCertExt"),

	/** Role Spec Cert Identifier */
	ROLE_SPECIFICATION_CERTIFICATE_IDENTIFIER("2.5.29.39", "RoleSpecificationCertificateIdentifierCertExt"),

	/** CRL Stream Identifier */
	CRL_STREAM_IDENTIFIER("2.5.29.40", "CrlStreamIdentifierCertExt"),

	/** Basic Att Constraints Identifier */
	BASIC_ATT_CONSTRAINTS("2.5.29.41", "BaseAttConstraintsCertExt"),

	/** Delegated Name Constraints */
	DELEGATED_NAME_CONSTRAINTS("2.5.29.42", "DelegatedNameConstraintsCertExt"),

	/** Time Specification */
	TIME_SPECIFICATION("2.5.29.43", "TimeSpecificationCertExt"),

	/** CRL Scope */
	CRL_SCOPE("2.5.29.44", "CrlScopeCertExt"),

	/** Status Referrals */
	STATUS_REFERRALS("2.5.29.45", "StatusReferralsCertExt"),

	/** Ordered List */
	ORDERED_LIST("2.5.29.47", "OrderedListCertExt"),

	/** Attribute Descriptor */
	ATTRIBUTE_DESCRIPTOR("2.5.29.48", "AttributeDescriptorCertExt"),

	/** User Notice */
	USER_NOTICE("2.5.29.49", "UserNoticeCertExt"),

	/** SOA Identifier */
	SOA_IDENTIFIER("2.5.29.50", "SoaIdentifierCertExt"),

	/** Base Update Time */
	BASE_UPDATE_TIME("2.5.29.51", "BaseUpdateTimeCertExt"),

	/** Acceptable Certificate Policies */
	ACCEPTABLE_CERTIFICATE_POLICIES("2.5.29.52", "AcceptableCertificatePoliciesCertExt"),

	/** Delta Information */
	DELTA_INFORMATION("2.5.29.53", "DeltaInformationCertExt"),

	/** Target Information */
	TARGET_INFORMATION("2.5.29.55", "TargetInformationCertExt"),

	/** No Revocation Availability */
	NO_REVOCATION_AVAILABILITY("2.5.29.56", "NoRevocationAvailabilityCertExt"),

	/** Acceptable Privilege Policies */
	ACCEPTABLE_PRIVILEGE_POLICIES("2.5.29.57", "AcceptablePrivilegePoliciesCertExt"),

	// ////////////////////////////////
	// Obsolete X509Extension OIDs
	// ////////////////////////////////

	/** Obsolete Authority Key Identifier */
	AUTHORITY_KEY_IDENTIFIER_OBS("2.5.29.1", "AuthorityKeyIdentifierObsCertExt"),

	/** Obsolete Primary Key Attributes */
	PRIMARY_KEY_ATTRIBUTES_OBS("2.5.29.2", "PrimaryKeyAttributesObsCertExt"),

	/** Obsolete Certificate Policies */
	CERTIFICATE_POLICIES_OBS("2.5.29.3", "CertificatePoliciesObsCertExt"),

	/** Obsolete Primary Key Usage Restriction */
	PRIMARY_KEY_USAGE_RESTRICTION_OBS("2.5.29.4", "PrimaryKeyUsageRestrictionObsCertExt"),

	/** Obsolete Policy Mappings */
	POLICY_MAPPINGS_OBS("2.5.29.5", "PolicyMappingsObsCertExt"),

	/** Obsolete Subtrees Constraint */
	SUBTREES_CONSTRAINT_OBS("2.5.29.6", "SubtreesConstraintObsCertExt"),

	/** Obsolete Subject Alternative Name */
	SUBJECT_ALTERNATIVE_NAME_OBS("2.5.29.7", "SubjectAlternativeNameObsCertExt"),

	/** Obsolete Issuer Alternative Name */
	ISSUER_ALTERNATIVE_NAME_OBS("2.5.29.8", "IssuerAlternativeNameObsCertExt"),

	/** Obsolete Basic Constraints */
	BASIC_CONSTRAINTS_OBS("2.5.29.10", "BasicConstraintsObsCertExt"),

	/** Obsolete Name Constraints */
	NAME_CONSTRAINTS_OBS("2.5.29.11", "NameConstraintsObsCertExt"),

	/** Obsolete Policy Constraints */
	POLICY_CONSTRAINTS_OBS("2.5.29.12", "PolicyConstraintsObsCertExt"),

	/** Additional Obsolete Basic Constraints */
	BASIC_CONSTRAINTS_OBS1("2.5.29.13", "BasicConstraintsObsCertExt"),

	/** Obsolete Expiration Date */
	EXPIRATION_DATE_OBS("2.5.29.22", "ExpirationDateObsCertExt"),

	/** Obsolete CRL Distribution Points */
	CRL_DISTRIBUTION_POINTS_OBS("2.5.29.25", "CrlDistributionPointsObsCertExt"),

	/** Obsolete Issuing Distribution Point */
	ISSUING_DISTRIBUTION_POINT_OBS("2.5.29.26", "IssuingDistributionPointObsCertExt"),

	/** Additional Obsolete Policy Constraints */
	POLICY_CONSTRAINTS_OBS1("2.5.29.34", "PolicyConstraintsObsCertExt"),


	// ////////////////////////////////
	// RFC3739 QC PRIVATE EXTENSIONS
	// ////////////////////////////////

	/** Stores biometric information for authentication purposes. */
	BIOMETRIC_INFO("1.3.6.1.5.5.7.1.2", "BiometricInfo"),

	/** Indicates that the certificate is a Qualified Certificate in accordance with a particular legal system. */
	QC_STATEMENTS("1.3.6.1.5.5.7.1.3", "QCStatements"),


	// ////////////////////////////////
	// RFC2560 PRIVATE EXTENSIONS
	// ////////////////////////////////

	/** A CA specifies by including this extension in the certificate of an OCSP responder that the requester can trust
	   the certificate and need not obtain revocation information. */
	OCSP_NO_CHECK("1.3.6.1.5.5.7.48.1.5", "OCSPNoCheck"),


	// ////////////////////////////////
	// COMMON PKI 2.0
	// ////////////////////////////////

	LIABILITY_LIMITATION_FLAG("0.2.262.1.10.12.0", "LiabilityLimitationFlag"),
	DATE_OF_CERT_GEN("1.3.36.8.3.1", "DateOfCertGen"),
	PROCURATION("1.3.36.8.3.2", "Procuration"),
	ADMISSION("1.3.36.8.3.3", "Admission"),
	MONETARY_LIMIT("1.3.36.8.3.4", "MonetaryLimit"),
	DECLARATION_OF_MAJORITY("1.3.36.8.3.5", "DeclarationOfMajority"),
	ICCSN("1.3.36.8.3.5", "ICCSN"),
	RESTRICTION("1.3.36.8.3.8", "Restriction"),
	ADDITIONAL_INFORMATION("1.3.36.8.3.15", "AdditionalInformation"),


	// ////////////////////////////////
	// CDC (TU Darmstadt)
	// ////////////////////////////////

	VALIDITY_MODEL("1.3.6.1.4.1.8301.3.5", "ValidityModel"),


	// ////////////////////////////////
	// Microsoft
	// ////////////////////////////////

	MS_ENROLL_CERT_TYPE_EXTENSION("1.3.6.1.4.1.311.20.2", "MSEnrollCerttypeExtension"),
	MS_CA_VERSION("1.3.6.1.4.1.311.21.1", "MSCaVersion"),
	MS_CA_CERTIFICATE_HASH("1.3.6.1.4.1.311.21.2", "MSCACertificateHash"),
	MS_CRL_NEXT_PUBLISH("1.3.6.1.4.1.311.21.4", "MSCRLNextPublish"),
	MS_CERTIFICATE_TEMPLATE("1.3.6.1.4.1.311.21.7", "MSCertificateTemplate"),
	MS_APPLICATION_POLICIES("1.3.6.1.4.1.311.21.10", "MSApplicationPolicies"),


	// ////////////////////////////////
	// RFC 3851
	// ////////////////////////////////

	SMIME_CAPABILITIES("1.2.840.113549.1.9.15", "SMIMECapabilities"),


	// ////////////////////////////////
	// RFC 3709
	// ////////////////////////////////

	LOGO_TYPE("1.3.6.1.5.5.7.1.12", "LogoType"),


	// ////////////////////////////////
	// SET (Secure Electronic Transaction)
	// ////////////////////////////////

	SET_HASHED_ROOT_KEY("2.23.42.7.0", "SETHashedRootKey"),
	SET_CERTIFICATE_TYPE("2.23.42.7.1", "SETCertificateType"),
	SET_MERCHANT_DATA("2.23.42.7.2", "SETMerchantData"),
	SET_CARD_CERT_REQUIRED("2.23.42.7.3", "SETCardCertRequired"),
	SET_TUNNELING("2.23.42.7.4", "SETTunneling"),
	SET_SET_EXTENSIONS("2.23.42.7.5", "SETSetExtensions"),
	SET_SET_QUALIFIER("2.23.42.7.6", "SETSetQualifier"),


	// ////////////////////////////////
	// VeriSign
	// ////////////////////////////////

	VS_CZAG("2.16.840.1.113733.1.6.3", "VeriSignCZAG"),
	VS_NON_VERIFIED("2.16.840.1.113733.1.6.4", "VeriSignNonVerified"),
	VS_FIDELITY_TOKEN("2.16.840.1.113733.1.6.5", "VeriSignFidelityToken"),
	VS_IN_BOX_V1("2.16.840.1.113733.1.6.6", "VeriSignInBoxV1"),
	VS_SERIAL_NUMBER_ROLLOVER("2.16.840.1.113733.1.6.7", "VeriSignSerialNumberRollover"),
	VS_TOKEN_TYPE("2.16.840.1.113733.1.6.8", "VeriSignTokenType"),
	VS_IN_BOX_V2("2.16.840.1.113733.1.6.10", " VeriSignNetscapeInBoxV2"),
	VS_ON_SITE_JURISDICTION_HASH("2.16.840.1.113733.1.6.11", "VeriSignOnSiteJurisdictionHash"),
	VS_UNKNOWN("2.16.840.1.113733.1.6.13", "VeriSignUnknown"),
	VS_DNB_DUNS_NUMBER("2.16.840.1.113733.1.6.15", "VeriSignDnbDunsNumber"),

	// ////////////////////////////////
	// Google, RFC 6962 "Certificate Transparency"
	// ////////////////////////////////

	GO_CT_SCTS("1.3.6.1.4.1.11129.2.4.2", "SignedCertificateTimestampList"),

	// ////////////////////////////////
	// Apple, see CPS: http://images.apple.com/certificateauthority/pdf/Apple_Developer_ID_CPS_v3.2.pdf
	// ////////////////////////////////

	APPLE_CODE_SIGNING("1.2.840.113635.100.6.1.13", "AppleApplicationCodeSigning"),
	APPLE_INSTALLER_SIGNING("1.2.840.113635.100.6.1.14", "AppleInstallerPackageSigning"),
	APPLE_DEV_PROGRAM("1.2.840.113635.100.6.2.6", "AppleDevProgram"),

	// for letting the user add an arbitrary extension
	CUSTOM("0", "custom"),

	UNKNOWN("0", "unknown");


	// @formatter:on

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
    private String oid;
    private String friendlyKey;

    X509ExtensionType(String oid, String friendlyKey) {
        this.oid = oid;
        this.friendlyKey = friendlyKey;
    }

    /**
     * Get type's Object Identifier.
     *
     * @return Object Identifier
     */
    public String oid() {
        return oid;
    }

    /**
     * Get type's friendly name.
     *
     * @return Friendly name
     */
    public String friendly() {

        String friendlyName = friendlyKey;
        if (res.containsKey(friendlyKey)) {
            friendlyName = res.getString(friendlyKey);
        }

        return friendlyName;
    }

    /**
     * Resolve the supplied object identifier to a matching type.
     *
     * @param oid Object identifier
     * @return Type or null if none
     */
    public static X509ExtensionType resolveOid(String oid) {
        for (X509ExtensionType type : values()) {
            if (oid.equals(type.oid())) {
                return type;
            }
        }

        return UNKNOWN;
    }

    /**
     * Returns friendly name.
     *
     * @return Friendly name
     */
    @Override
    public String toString() {
        return friendly();
    }
}
