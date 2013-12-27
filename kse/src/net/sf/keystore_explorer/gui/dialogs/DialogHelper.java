package net.sf.keystore_explorer.gui.dialogs;

import java.security.PrivateKey;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JTextField;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.KeyInfo;
import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.crypto.keypair.KeyPairUtil;
import net.sf.keystore_explorer.crypto.signing.SignatureType;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * Helper class that bundles redundant code from the dialogs.
 *
 */
public class DialogHelper {


	/**
	 * Populates a JTextField with PKCS#10 challenge
	 * 
	 * @param attributes 
	 * 				Attributes from CSR
	 * @param textField 
	 * 				Text field to be populated with the challenge
	 */
	public static void populatePkcs10Challenge(Attribute[] attributes, JTextField textField) {
		
		if (attributes != null) {
			for (Attribute attribute : attributes) {

				ASN1ObjectIdentifier attributeOid = attribute.getAttrType();

				if (attributeOid.equals((PKCSObjectIdentifiers.pkcs_9_at_challengePassword))) {
					ASN1Encodable challenge = attribute.getAttributeValues()[0];

					// Challenge can be one of two different types of string
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
	
	/**
	 * Populate a JComboBox with signature algorithms depending on the key pair type.
	 * 
	 * @param keyPairType
	 * @param privateKey
	 * @param jcbSignatureAlgorithm
	 * @throws CryptoException
	 */
	public static void populateSigAlgs(KeyPairType keyPairType, PrivateKey privateKey, JComboBox jcbSignatureAlgorithm) 
			throws CryptoException {
		
		List<SignatureType> sigAlgs;

		switch (keyPairType) {
		case RSA:
			KeyInfo keyInfo = KeyPairUtil.getKeyInfo(privateKey);
			sigAlgs = SignatureType.rsaSignatureTypes(keyInfo.getSize());
			break;
		case DSA:
			sigAlgs = SignatureType.dsaSignatureTypes();
			break;
		case EC:
		default:
			sigAlgs = SignatureType.ecdsaSignatureTypes();
		}

		jcbSignatureAlgorithm.removeAllItems();

		for (SignatureType sigAlg : sigAlgs) {
			jcbSignatureAlgorithm.addItem(sigAlg);
		}

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
