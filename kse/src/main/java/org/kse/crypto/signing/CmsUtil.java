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
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.kse.crypto.CryptoException;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

/**
 * Provides utility methods relating to Cryptographic Message Syntax (CMS).
 */
public class CmsUtil {
    private static final String CMS_PEM_TYPE = "CMS";
    private static final String PKCS7_PEM_TYPE = "PKCS7";

    private CmsUtil() {
    }

    /**
     * PEM encode a CMS signature.
     *
     * @param cms The CMS signature
     * @return The PEM'd encoding
     */
    public static String getPem(CMSSignedData cms) throws CryptoException {
        // Use PKCS7 PEM header since it can be verified using GnuTLS certtool and OpenSSL.
        // GnuTLS certtool cannot verify signatures with the CMS PEM header.
        try {
            PemInfo pemInfo = new PemInfo(PKCS7_PEM_TYPE, null, cms.getEncoded());
            return PemUtil.encode(pemInfo);
        } catch (IOException e) {
            // TODO JW Auto-generated catch block
            throw new CryptoException(e);
        }
    }

    /**
     * Extracts the signature signing time, if present, from the signature's signed attributes.
     *
     * @param signerInfo The signer information.
     * @return The signing time, if present, else null.
     */
    public static Date getSigningTime(SignerInformation signerInfo) throws CryptoException {
        Date signingTime = null;
        AttributeTable signedAttributes = signerInfo.getSignedAttributes();

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
                        // TODO JW Auto-generated catch block
                        throw new CryptoException(e);
                    }
                }
            }
        }
        return signingTime;
    }

    /**
     * Extracts the time stamp token, if present, from the signature's unsigned attributes.
     *
     * @param signerInfo The signer information.
     * @return The time stamp token as TimeStampToken, if present, else null.
     */
    public static TimeStampToken getTimeStampToken(SignerInformation signerInfo) throws CryptoException
    {
        TimeStampToken timeStampToken = null;
        AttributeTable unsignedAttributes = signerInfo.getUnsignedAttributes();
        if (unsignedAttributes != null) {
            Attribute tsTokenAttribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            if (tsTokenAttribute != null) {
                try {
                    timeStampToken = new TimeStampToken(ContentInfo.getInstance(tsTokenAttribute.getAttributeValues()[0]));
                } catch (TSPException | IOException e) {
                    // TODO JW Auto-generated catch block
                    throw new CryptoException(e);
                }
            }
        }
        return timeStampToken;
    }

    /**
     * Extracts the time stamp token, if present, from the signature's unsigned attributes.
     *
     * @param signerInfo The signer information.
     * @return The time stamp token as CMSSignedData, if present, else null.
     */
    public static CMSSignedData getTimeStampSignature(SignerInformation signerInfo) throws CryptoException
    {
        CMSSignedData timeStampToken = null;
        AttributeTable unsignedAttributes = signerInfo.getUnsignedAttributes();
        if (unsignedAttributes != null) {
            Attribute tsTokenAttribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            if (tsTokenAttribute != null) {
                try {
                    timeStampToken = new CMSSignedData(ContentInfo.getInstance(tsTokenAttribute.getAttributeValues()[0]));
                } catch (CMSException e) {
                    // TODO JW Auto-generated catch block
                    throw new CryptoException(e);
                }
            }
        }
        return timeStampToken;
    }
}
