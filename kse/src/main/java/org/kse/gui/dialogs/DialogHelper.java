/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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
package org.kse.gui.dialogs;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Collections;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JTextField;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.ecc.CurveSet;
import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.ecc.EdDSACurves;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.preferences.PreferencesManager;

/**
 * Helper class that bundles redundant code from the dialogs.
 */
public class DialogHelper {

    private static final String SM2_SUFFIX = "_SM2";

    private DialogHelper() {
    }

    /**
     * Populate a JComboBox with signature algorithms depending on the key pair type.
     *
     * @param keyPairType The key pair type of the signing private key.
     * @param privateKey  The signing private key.
     * @param jcbSignatureAlgorithm The JComboBox to be populated with the signature algorithms.
     */
    public static void populateSigAlgs(KeyPairType keyPairType, PrivateKey privateKey,
                                       JComboBox<SignatureType> jcbSignatureAlgorithm) {

        List<SignatureType> sigAlgs;
        String prefsKey = keyPairType.name();

        switch (keyPairType) {
        case DSA:
            sigAlgs = SignatureType.dsaSignatureTypes();
            break;
        case ECDSA:
            // map ECDSA to EC for consistency
            prefsKey = KeyPairType.EC.name();
            // fall-through
        case EC:
            // SM2 is an EC curve, but it is used with a different set of signature algorithms
            String curve = EccUtil.getNamedCurve(privateKey);
            if (CurveSet.SM2.getAllCurveNames().contains(curve)) {
                sigAlgs = SignatureType.sm2SignatureTypes();
                prefsKey += SM2_SUFFIX;
            } else {
                sigAlgs = SignatureType.ecdsaSignatureTypes();
            }
            break;
        case EDDSA:
            EdDSACurves edDSACurve = EccUtil.detectEdDSACurve(privateKey);
            if (edDSACurve == EdDSACurves.ED25519) {
                sigAlgs = Collections.singletonList(SignatureType.ED25519);
            } else {
                sigAlgs = Collections.singletonList(SignatureType.ED448);
            }
            break;
        case ED25519:
            sigAlgs = Collections.singletonList(SignatureType.ED25519);
            break;
        case ED448:
            sigAlgs = Collections.singletonList(SignatureType.ED448);
            break;
        case ECGOST3410:
            sigAlgs = Collections.singletonList(SignatureType.GOST3411_GOST3410);
            break;
        case ECGOST3410_2012:
            ECPrivateKey privk = (ECPrivateKey) privateKey;
            if (privk.getParams().getOrder().bitLength() > 256) {
                sigAlgs = Collections.singletonList(SignatureType.GOST3411_2012_512_GOST3410_2012);
            } else {
                sigAlgs = Collections.singletonList(SignatureType.GOST3411_2012_256_GOST3410_2012);
            }
            break;
        case MLDSA44:
            sigAlgs = Collections.singletonList(SignatureType.MLDSA44);
            break;
        case MLDSA65:
            sigAlgs = Collections.singletonList(SignatureType.MLDSA65);
            break;
        case MLDSA87:
            sigAlgs = Collections.singletonList(SignatureType.MLDSA87);
            break;
        case MLKEM512:
        case MLKEM768:
        case MLKEM1024:
            // ML-KEM is for key exchange not signing
            sigAlgs = Collections.EMPTY_LIST;
            break;
        case SLHDSA_SHA2_128S:
        case SLHDSA_SHA2_128F:
        case SLHDSA_SHA2_192S:
        case SLHDSA_SHA2_192F:
        case SLHDSA_SHA2_256S:
        case SLHDSA_SHA2_256F:
        case SLHDSA_SHAKE_128S:
        case SLHDSA_SHAKE_128F:
        case SLHDSA_SHAKE_192S:
        case SLHDSA_SHAKE_192F:
        case SLHDSA_SHAKE_256S:
        case SLHDSA_SHAKE_256F:
            sigAlgs = Collections.singletonList(SignatureType.SLHDSA);
            break;
        case RSA:
        default:
            try {
                KeyInfo keyInfo = KeyPairUtil.getKeyInfo(privateKey);
                sigAlgs = SignatureType.rsaSignatureTypes(keyInfo.getSize());
            } catch (CryptoException e) {
                sigAlgs = Collections.emptyList();
            }
        }

        jcbSignatureAlgorithm.removeAllItems();

        for (SignatureType sigAlg : sigAlgs) {
            jcbSignatureAlgorithm.addItem(sigAlg);
        }

        // Skip all this work if it's not needed (e.g., EdDSA, ML-DSA, SLH-DSA)
        if (sigAlgs.size() > 1) {
            SignatureType savedAlgorithm = PreferencesManager.getPreferences().getSignatureTypes().get(prefsKey);
            // Checking for existence is only here to support the case when a signature algorithm
            // is removed in the future and a new good default needs to be chosen.
            if (savedAlgorithm != null && sigAlgs.contains(savedAlgorithm)) {
                jcbSignatureAlgorithm.setSelectedItem(savedAlgorithm);
            } else {
                // pre-select modern hash algs
                if (sigAlgs.contains(SignatureType.SHA256_RSA)) {
                    jcbSignatureAlgorithm.setSelectedItem(SignatureType.SHA256_RSA);
                } else if (sigAlgs.contains(SignatureType.SHA256_ECDSA)) {
                    jcbSignatureAlgorithm.setSelectedItem(SignatureType.SHA256_ECDSA);
                } else if (sigAlgs.contains(SignatureType.SHA256_DSA)) {
                    jcbSignatureAlgorithm.setSelectedItem(SignatureType.SHA256_DSA);
                } else {
                    jcbSignatureAlgorithm.setSelectedIndex(0);
                }
            }
        }
    }

    /**
     * Remembers the user's chosen signature algorithm for the key pair type.
     *
     * @param keyPairType The key pair type.
     * @param privateKey  The signing private key.
     * @param signatureAlgorithm The signature algorithm to be remembered.
     */
    public static void rememberSigAlg(KeyPairType keyPairType, PrivateKey privateKey, SignatureType signatureAlgorithm) {
        String prefsKey = keyPairType.name();

        switch (keyPairType) {
        case ECDSA:
            // map ECDSA to EC for consistency
            prefsKey = KeyPairType.EC.name();
            // fall-through
        case EC:
            // SM2 is an EC curve, but it is used with a different set of signature algorithms
            String curve = EccUtil.getNamedCurve(privateKey);
            if (CurveSet.SM2.getAllCurveNames().contains(curve)) {
                prefsKey += SM2_SUFFIX;
            }
            // fall-through
        case RSA:
        case DSA:
            PreferencesManager.getPreferences().getSignatureTypes().put(prefsKey, signatureAlgorithm);
            break;
        default:
            // Don't save the user's choice since there's only one option
            // Technically, the drop down does not have to be displayed, but
            // it's nice for users to see the signature algorithm being used.
            break;
        }
    }

    /**
     * Populates a JTextField with PKCS#10 challenge
     *
     * @param attributes Attributes from CSR
     * @param textField  Text field to be populated with the challenge
     */
    public static void populatePkcs10Challenge(Attribute[] attributes, JTextField textField) {

        ASN1ObjectIdentifier pkcs9AtChallengePassword = PKCSObjectIdentifiers.pkcs_9_at_challengePassword;
        populateTextField(attributes, textField, pkcs9AtChallengePassword);
    }

    /**
     * Populates a JTextField with PKCS#10/#9 unstructuredName
     *
     * @param attributes Attributes from CSR
     * @param textField  Text field to be populated with the unstructuredName
     */
    public static void populatePkcs10UnstructuredName(Attribute[] attributes, JTextField textField) {

        ASN1ObjectIdentifier pkcs9UnstructureName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;
        populateTextField(attributes, textField, pkcs9UnstructureName);
    }

    private static void populateTextField(Attribute[] attrs, JTextField textField, ASN1ObjectIdentifier pkcs9Attr) {
        if (attrs != null) {
            for (Attribute attribute : attrs) {

                ASN1ObjectIdentifier attributeOid = attribute.getAttrType();

                if (attributeOid.equals(pkcs9Attr)) {
                    ASN1Encodable challenge = attribute.getAttributeValues()[0];

                    // data type can be one of IA5String or UTF8String
                    if (challenge instanceof DERPrintableString) {
                        textField.setText(((DERPrintableString) challenge).getString());
                    } else if (challenge instanceof DERUTF8String) {
                        textField.setText(((DERUTF8String) challenge).getString());
                    }
                    textField.setCaretPosition(0);
                }
            }
        }
    }
}
