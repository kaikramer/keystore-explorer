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
package org.kse.crypto.signing;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.utilities.StringUtils;
import org.kse.utilities.io.HexUtil;

/**
 * A SignerInformation extension for UI / verification needs.
 */
public class KseSignerInformation extends SignerInformation {

    private Store<X509CertificateHolder> trustedCerts;
    private Store<X509CertificateHolder> signatureCerts;
    private X509CertificateHolder cert;
    private CmsSignatureStatus status;
    private boolean trustedCert;

    /**
     * Creates a new instance.
     *
     * @param signerInfo The SignerInformation to extend.
     * @param trustedCerts The trusted certs for lookup and verification.
     * @param signatureCerts The signature certs for lookup and verification.
     */
    public KseSignerInformation(SignerInformation signerInfo, Store<X509CertificateHolder> trustedCerts,
            Store<X509CertificateHolder> signatureCerts) {
        super(signerInfo);
        this.trustedCerts = trustedCerts;
        this.signatureCerts = signatureCerts;
        lookupCert();
    }

    /**
     * @return the trustedCerts
     */
    public Store<X509CertificateHolder> getTrustedCerts() {
        return trustedCerts;
    }

    /**
     * @return the signatureCerts
     */
    public Store<X509CertificateHolder> getSignatureCerts() {
        return signatureCerts;
    }

    /**
     * @return the cert
     */
    public X509CertificateHolder getCertificate() {
        return cert;
    }

    /**
     * @return the signature status
     */
    public CmsSignatureStatus getStatus() {
        if (status == null) {
            verify();
        }
        return status;
    }

    private void lookupCert() {

        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> matchedCerts1 = trustedCerts.getMatches(getSID());

        if (!matchedCerts1.isEmpty()) {
            cert = matchedCerts1.iterator().next();

            // TODO JW Need to trace the signature cert to a self-signed or CA cert, check basic constraints.
            trustedCert = true;
        } else {
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> matchedCerts2 = signatureCerts.getMatches(getSID());

            if (!matchedCerts2.isEmpty()) {
                cert = matchedCerts2.iterator().next();
            }
        }
    }

    /**
     *
     * @return The short name for user interfaces.
     */
    public String getShortName() {
        String shortName;

        if (cert != null) {
            shortName = getShortName(cert);
        } else {
            shortName = HexUtil.getHexString(getSID().getSerialNumber(), "0x", 0, 0);
        }

        return shortName;
    }

    private static String getShortName(X509CertificateHolder cert) {
        X500Name subject = cert.getSubject();

        String shortName = X500NameUtils.extractCN(subject);
        String emailAddress = X500NameUtils.extractEmailAddress(subject);

        if (!StringUtils.isBlank(emailAddress)) {
            if (StringUtils.isBlank(shortName)) {
                shortName = emailAddress;
            } else {
                shortName += " <" + emailAddress + ">";
            }
        }

        if (StringUtils.isBlank(shortName)) {
            shortName = subject.toString();
        }

        // subject DN can be empty in some cases
        if (StringUtils.isBlank(shortName)) {
            shortName = cert.getSerialNumber().toString();
        }

        return shortName;
    }

    /**
     * Extracts the signature signing time, if present, from the signature's signed attributes.
     *
     * @return The signing time, if present, else null.
     */
    public Date getSigningTime() {
        Date signingTime = null;
        AttributeTable signedAttributes = getSignedAttributes();

        if (signedAttributes != null) {
            Attribute signingTimeAttribute = signedAttributes.get(CMSAttributes.signingTime);
            if (signingTimeAttribute != null) {
                Enumeration<?> element = signingTimeAttribute.getAttrValues().getObjects();
                if (element.hasMoreElements()) {
                    Object o = element.nextElement();
                    try {
                        if (o instanceof ASN1UTCTime) {
                            signingTime = ((ASN1UTCTime) o).getAdjustedDate();
                        } else if (o instanceof ASN1GeneralizedTime) {
                            signingTime = ((ASN1GeneralizedTime) o).getDate();
                        }
                    } catch (ParseException e) {
                        // Users are not going to know what to do about invalid ASN.1 date structures.
                        // So ignore the exception.
                    }
                }
            }
        }
        return signingTime;
    }

    /**
     * Extracts the time stamp token, if present, from the signature's unsigned
     * attributes.
     *
     * @return The time stamp token as ContentInfo, if present, else null.
     */
    public ContentInfo getTimeStamp() {

        AttributeTable unsignedAttributes = getUnsignedAttributes();

        if (unsignedAttributes != null) {
            Attribute tsTokenAttribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            if (tsTokenAttribute != null) {
                return ContentInfo.getInstance(tsTokenAttribute.getAttributeValues()[0]);
            }
        }

        return null;
    }

    private void verify() {

        status = CmsSignatureStatus.NOT_VERIFIED;

        if (cert != null) {

            boolean verified = false;

            try {
                // TODO JW - Should a provider be specified for the JcaSimpleSingerInfoVerifierBuilder?
                if (verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))) {
                    verified = true;

                    // TODO JW Display TS validation status on form.
                    verifyTimeStamp();

                    if (getCounterSignatures().size() > 0) {

                        Collection<KseSignerInformation> counterSigners = CmsUtil.convertSignerInformations(
                                getCounterSignatures().getSigners(), trustedCerts, signatureCerts);

                        verified &= verify(counterSigners);
                    }
                }
            } catch (Exception e) {
                verified = false;
            }

            if (verified) {
                if (trustedCert) {
                    status = CmsSignatureStatus.VALID_TRUSTED;
                } else {
                    status = CmsSignatureStatus.VALID_NOT_TRUSTED;
                }
            } else {
                status = CmsSignatureStatus.INVALID;
            }

        }
    }

    private boolean verify(Collection<KseSignerInformation> signers) throws OperatorCreationException,
            CertificateException, TSPValidationException, CMSException, IOException, TSPException {

        boolean verified = true;

        for (KseSignerInformation signer : signers) {
            signer.verify();

            verified &= (signer.getStatus() == CmsSignatureStatus.VALID_NOT_TRUSTED
                    || signer.getStatus() == CmsSignatureStatus.VALID_TRUSTED);
        }

        return verified;
    }

    private void verifyTimeStamp()
            throws TSPException, IOException, TSPValidationException, OperatorCreationException, CertificateException {

        ContentInfo timeStamp = getTimeStamp();

        if (timeStamp != null) {
            TimeStampToken tspToken = new TimeStampToken(timeStamp);

            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> matchedCerts = tspToken.getCertificates().getMatches(tspToken.getSID());
            if (!matchedCerts.isEmpty()) {
                X509CertificateHolder cert = matchedCerts.iterator().next();
                tspToken.validate(new JcaSimpleSignerInfoVerifierBuilder().build(cert));
            }
        }
    }
}
