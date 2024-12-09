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

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;

/**
 * Class provides functionality to sign files using PKCS #7 Cryptographic
 * Message Syntax (CMS).
 */
public class CmsSigner {

    /**
     * Signs a file using PKCS #7 CMS.
     *
     * @param inputFile         The file to sign.
     * @param outputFile        The output file for the signature.
     * @param privateKey        The private key to use for signing.
     * @param certificateChain  The certificate chain for the private key.
     * @param detachedSignature True if the signature is to be detached. False,
     *                          encapsulate the file into the signature.
     * @param signatureType     The signature type to use for signing.
     * @param tsaUrl            An optional TSA URL for adding a time stamp token to
     *                          the signature.
     * @param provider
     */
    public static CMSSignedData sign(File inputFile, PrivateKey privateKey, X509Certificate[] certificateChain,
            boolean detachedSignature, SignatureType signatureType, String tsaUrl, Provider provider)
            throws CryptoException {
        try {
            CMSTypedData msg = new CMSProcessableFile(inputFile);

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureType.jce()).build(privateKey);
            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                            .build(contentSigner, certificateChain[0]));
            generator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

            CMSSignedData signedData = generator.generate(msg, !detachedSignature);

            if (tsaUrl != null) {
                signedData = addTimestamp(tsaUrl, signedData);
            }

            return signedData;
        } catch (Exception e) {
            // TODO JW - Create exception message
            throw new CryptoException("TODO");
        }
    }

    public static CMSSignedData counterSign(CMSSignedData signedData, PrivateKey privateKey,
            X509Certificate[] certificateChain, boolean detachedSignature, SignatureType signatureType, String tsaUrl,
            Provider provider) throws CryptoException {
        try {
            CMSSignedDataGenerator counterSignerGen = new CMSSignedDataGenerator();
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureType.jce()).build(privateKey);
            counterSignerGen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                            .build(contentSigner, certificateChain[0]));

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            for (SignerInformation signer : signedData.getSignerInfos()) {
                SignerInformationStore counterSigners = counterSignerGen.generateCounterSigners(signer);
                signer = SignerInformation.addCounterSigners(signer, counterSigners);

                generator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));
                generator.addSigners(new SignerInformationStore(signer));
            }
            generator.addCertificates(signedData.getCertificates());

            CMSSignedData counterSignedData = generator.generate(signedData.getSignedContent(), !detachedSignature);

            // TODO JW - is it possible to add a timestamp for a counter signature? The current logic drops the counter signer.
//            if (tsaUrl != null) {
//                counterSignedData = addTimestamp(tsaUrl, counterSignedData);
//            }

            return counterSignedData;
        } catch (CertificateEncodingException | OperatorCreationException | CMSException e) {
            // TODO Auto-generated catch block
            throw new CryptoException("TODO");
        }
    }

    /**
     * Adds a timestamp to a PKCS #7 signature.
     *
     * @param tsaUrl     The URL of the time stamp authority
     * @param signedData The signature to time stamp.
     * @return <b>CMSSignedData</b> with time stamp.
     */
    public static CMSSignedData addTimestamp(String tsaUrl, CMSSignedData signedData) throws IOException {

        Collection<SignerInformation> signerInfos = signedData.getSignerInfos().getSigners();

        // get signature of first signer (should be the only one)
        SignerInformation si = signerInfos.iterator().next();
        byte[] signature = si.getSignature();

        // send request to TSA
        byte[] token = TimeStampingClient.getTimeStampToken(tsaUrl, signature, DigestType.SHA256);

        // create new SignerInformation with TS attribute
        Attribute tokenAttr = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                new DERSet(ASN1Primitive.fromByteArray(token)));
        ASN1EncodableVector timestampVector = new ASN1EncodableVector();
        timestampVector.add(tokenAttr);
        AttributeTable at = new AttributeTable(timestampVector);
        si = SignerInformation.replaceUnsignedAttributes(si, at);
        signerInfos.clear();
        signerInfos.add(si);
        SignerInformationStore newSignerStore = new SignerInformationStore(signerInfos);

        // create new signed data
        return CMSSignedData.replaceSigners(signedData, newSignerStore);
    }
}
