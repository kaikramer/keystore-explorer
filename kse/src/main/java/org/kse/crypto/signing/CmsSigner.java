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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.ResourceBundle;

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
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/signing/resources");

    private CmsSigner() {
    }

    /**
     * Signs a file using PKCS #7 CMS.
     *
     * @param inputFile         The file to sign.
     * @param privateKey        The private key to use for signing.
     * @param certificateChain  The certificate chain for the private key.
     * @param detachedSignature True if the signature is to be detached. False,
     *                          encapsulate the file into the signature.
     * @param signatureType     The signature type to use for signing.
     * @param tsaUrl            An optional TSA URL for adding a time stamp token to
     *                          the signature.
     * @param provider
     * @return The signature in a CMSSignedData object.
     */
    public static CMSSignedData sign(File inputFile, PrivateKey privateKey, X509Certificate[] certificateChain,
            boolean detachedSignature, SignatureType signatureType, String tsaUrl, Provider provider)
            throws CryptoException {
        try {
            CMSTypedData msg = new CMSProcessableFile(inputFile);

            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(signatureType.jce());
            JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
            if (provider != null) {
                contentSignerBuilder.setProvider(provider);
                digestCalculatorProviderBuilder.setProvider(provider);
            }

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculatorProviderBuilder.build())
                    .build(contentSignerBuilder.build(privateKey), certificateChain[0]));
            generator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

            CMSSignedData signedData = generator.generate(msg, !detachedSignature);

            if (tsaUrl != null) {
                SignerInformationStore signerInfos = addTimestamp(tsaUrl, signedData.getSignerInfos(),
                        signatureType.digestType());
                signedData = CMSSignedData.replaceSigners(signedData, signerInfos);
            }

            return signedData;
        } catch (Exception e) {
            throw new CryptoException(res.getString("CmsSignatureFailed.exception.message"), e);
        }
    }

    /**
     * Counter signs a signature using PKCS #7 CMS.
     *
     * @param signedData        The signature to counter sign.
     * @param privateKey        The private key to use for signing.
     * @param certificateChain  The certificate chain for the private key.
     * @param detachedSignature True if the signature is to be detached. False,
     *                          encapsulate the file into the signature.
     * @param signatureType     The signature type to use for signing.
     * @param tsaUrl            An optional TSA URL for adding a time stamp token to
     *                          the signature.
     * @param provider
     * @return The counter signed signature in a CMSSignedData object.
     */
    public static CMSSignedData counterSign(CMSSignedData signedData, PrivateKey privateKey,
            X509Certificate[] certificateChain, boolean detachedSignature, SignatureType signatureType, String tsaUrl,
            Provider provider) throws CryptoException {
        try {
            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(signatureType.jce());
            JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
            if (provider != null) {
                contentSignerBuilder.setProvider(provider);
                digestCalculatorProviderBuilder.setProvider(provider);
            }

            CMSSignedDataGenerator counterSignerGen = new CMSSignedDataGenerator();
            counterSignerGen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(digestCalculatorProviderBuilder.build())
                            .build(contentSignerBuilder.build(privateKey), certificateChain[0]));

            // Counter signs all existing signatures.
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            for (SignerInformation signer : signedData.getSignerInfos()) {
                SignerInformationStore counterSigners = counterSignerGen.generateCounterSigners(signer);

                if (tsaUrl != null) {
                    counterSigners = addTimestamp(tsaUrl, counterSigners, signatureType.digestType());
                }

                // addCounterSigners does not replace existing counter signers. It creates a new
                // counter signer vector if it does not already exist, and then it adds the counter signer.
                signer = SignerInformation.addCounterSigners(signer, counterSigners);

                generator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));
                generator.addSigners(new SignerInformationStore(signer));
            }
            generator.addCertificates(signedData.getCertificates());

            CMSSignedData counterSignedData = generator.generate(signedData.getSignedContent(), !detachedSignature);

            return counterSignedData;
        } catch (CertificateEncodingException | OperatorCreationException | CMSException | IOException e) {
            throw new CryptoException(res.getString("CmsCounterSignatureFailed.exception.message"), e);
        }
    }

    /**
     * Adds a timestamp to a PKCS #7 signature.
     *
     * @param tsaUrl      The URL of the time stamp authority.
     * @param signerInfos The signer information to time stamp.
     * @param digestType  The digest type to use for the time stamp.
     * @return <b>SignerInformation</b> with time stamp token.
     */
    public static SignerInformationStore addTimestamp(String tsaUrl, SignerInformationStore signerInfos,
            DigestType digestType) throws IOException {

        Collection<SignerInformation> newSignerInfos = new ArrayList<>();

        for (SignerInformation si : signerInfos.getSigners()) {
            byte[] signature = si.getSignature();

            // Ed448 uses digest type of SHAKE256-512, which is not currently supported by the TSAs.
            if (DigestType.SHAKE256 == digestType) {
                digestType = DigestType.SHA512;
            }

            // send request to TSA
            byte[] token = TimeStampingClient.getTimeStampToken(tsaUrl, signature, digestType);

            // create new SignerInformation with TS attribute
            Attribute tokenAttr = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                                                new DERSet(ASN1Primitive.fromByteArray(token)));
            ASN1EncodableVector timestampVector = new ASN1EncodableVector();
            timestampVector.add(tokenAttr);
            AttributeTable at = new AttributeTable(timestampVector);

            newSignerInfos.add(SignerInformation.replaceUnsignedAttributes(si, at));
        }

        return new SignerInformationStore(newSignerInfos);
    }
}
