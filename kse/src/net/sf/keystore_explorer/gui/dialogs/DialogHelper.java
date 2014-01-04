package net.sf.keystore_explorer.gui.dialogs;

import javax.swing.JTextField;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * Helper class that bundles redundant code from the dialogs.
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

	    ASN1ObjectIdentifier pkcs9AtChallengepassword = PKCSObjectIdentifiers.pkcs_9_at_challengePassword;
	    populateTextField(attributes, textField, pkcs9AtChallengepassword);
	}

	   /**
     * Populates a JTextField with PKCS#10/#9 unstructuredName
     *
     * @param attributes
     *              Attributes from CSR
     * @param textField
     *              Text field to be populated with the unstructuredName
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
