package org.kse.crypto.ecc;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.kse.crypto.CryptoTestsBase;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.utilities.oid.ObjectIdUtil;

import static org.assertj.core.api.Assertions.assertThat;

public class EccUtilTest extends CryptoTestsBase {

	@ParameterizedTest
	@ValueSource(strings = {
			"JKS",
			"JCEKS",
			"PKCS12",
			"BKS_V1",
			"BKS",
			"UBER",
			"PKCS11"
	})
	public void testIsEcAvailable(KeyStoreType keyStoreType) {
		assertThat(EccUtil.isECAvailable(keyStoreType)).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = {
		// SEC curves
		"secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2", "secp192k1",
		/* "secp192r1", = prime192v1 */ "secp224k1", "secp224r1", "secp256k1", /* "secp256r1", = prime256v1 */
		"secp384r1", "secp521r1", "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1", "sect163r1",
		"sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1",
		"sect409k1", "sect409r1", "sect571k1", "sect571r1",
		// ANSI X9.62 curves
		"prime192v1", "prime192v2", "prime192v3", "prime239v1", "prime239v2", "prime239v3", "prime256v1", "c2pnb163v1",
		"c2pnb163v2", "c2pnb163v3", "c2pnb176w1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3", "c2tnb239v1", "c2tnb239v2",
		"c2tnb239v3", "c2tnb359v1", "c2tnb431r1", "c2pnb208w1", "c2pnb272w1", "c2pnb304w1", "c2pnb368w1",
		// Brainpool curves
		"brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1", "brainpoolP192t1", "brainpoolP224r1", "brainpoolP224t1",
		"brainpoolP256r1", "brainpoolP256t1", "brainpoolP320r1", "brainpoolP320t1", "brainpoolP384r1", "brainpoolP384t1",
		"brainpoolP512r1", "brainpoolP512t1"
		// NIST curves are a subset of SEC curves (not explicitly tested here)
	})
	public void convertToECPrivateKeyStructure(String curveName) throws Exception {

		KeyPair keyPair = KeyPairUtil.generateECKeyPair(curveName, BC);
		ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

		byte[] encoded = EccUtil.convertToECPrivateKeyStructure(ecPrivateKey).toASN1Primitive().getEncoded();

		// verify ASN.1 structure "ECPrivateKey" from RFC 5915:
		//
		// ECPrivateKey ::= SEQUENCE {
	    //    version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
	    //    privateKey     OCTET STRING,
	    //    parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
	    //    publicKey  [1] BIT STRING OPTIONAL
	    // }
		//
	    // ECParameters ::= CHOICE {
	    //     namedCurve         OBJECT IDENTIFIER
	    //     -- implicitCurve   NULL
	    //     -- specifiedCurve  SpecifiedECDomain
	    //   }
		// RFC 5480:
	    // -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.

		ASN1Sequence sequence = ASN1Sequence.getInstance(encoded);

		// check version of data structure
		BigInteger version = ((ASN1Integer) sequence.getObjectAt(0)).getValue();
		assertThat(version).isEqualTo(BigInteger.ONE);

		// next is an octet string with the key
		assertThat(sequence.getObjectAt(1)).isInstanceOf(ASN1OctetString.class);

		// check for existence of (optional) EC parameters
		ASN1Encodable tagged0 = sequence.getObjectAt(2);
		DERTaggedObject derTaggedObject = (DERTaggedObject) tagged0;
		assertThat(derTaggedObject.getTagNo()).isEqualTo(0);

		// check that EC parameters contain the right curve name
		ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) derTaggedObject.getObject();
		String resolvedCurveName = ObjectIdUtil.toString(oid);
		assertThat(resolvedCurveName).containsIgnoringCase(curveName);
	}
}
