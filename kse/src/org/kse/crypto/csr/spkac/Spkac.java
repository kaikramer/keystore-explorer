/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
package org.kse.crypto.csr.spkac;

import static org.kse.crypto.csr.spkac.SpkacSubject.CN_PROPERTY;
import static org.kse.crypto.csr.spkac.SpkacSubject.C_PROPERTY;
import static org.kse.crypto.csr.spkac.SpkacSubject.L_PROPERTY;
import static org.kse.crypto.csr.spkac.SpkacSubject.OU_PROPERTY;
import static org.kse.crypto.csr.spkac.SpkacSubject.O_PROPERTY;
import static org.kse.crypto.csr.spkac.SpkacSubject.ST_PROPERTY;
import static org.kse.crypto.keypair.KeyPairType.DSA;
import static org.kse.crypto.keypair.KeyPairType.RSA;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;
import java.util.Properties;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.encoders.Base64;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.SignatureType;
import org.kse.utilities.io.HexUtil;
import org.kse.utilities.io.IOUtils;

/**
 * Signed Public Key and Challenge (SPKAC). Netscape's CSR format. SPKACs can be
 * created, outputted, loaded and verified using this class.
 *
 */
public class Spkac {
	// @formatter:off

	/*
	 * SPKAC ASN.1 structure:
	 *
	 * SignedPublicKeyAndChallenge ::= ASN1Sequence { publicKeyAndChallenge
	 * PublicKeyAndChallenge, signatureAlgorithm AlgorithmIdentifier, signature
	 * BIT STRING }
	 *
	 * PublicKeyAndChallenge ::= ASN1Sequence { spki SubjectPublicKeyInfo,
	 * challenge IA5STRING }
	 *
	 * SubjectPublicKeyInfo ::= ASN1Sequence { algorithm AlgorithmIdentifier,
	 * publicKey BIT STRING }
	 *
	 * AlgorithmIdentifier ::= ASN1Sequence { algorithm OBJECT IDENTIFIER,
	 * parameters ANY DEFINED BY algorithm OPTIONAL }
	 *
	 * AlgorithmIdentifier parameters for DSA:
	 *
	 * Dss-Parms ::= ASN1Sequence { p ASN1Integer, q ASN1Integer, g ASN1Integer
	 * }
	 *
	 * AlgorithmIdentifier parameters for RSA:
	 *
	 * Rsa-Params ::= ASN1Null
	 */

	// @formatter:on

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/csr/spkac/resources");

	private static final String SPKAC_PROPERTY = "SPKAC";
	private static final String NEWLINE = System.getProperty("line.separator");

	private String challenge;
	private SpkacSubject subject;
	private SignatureType signatureAlgorithm;
	private byte[] signature;
	private PublicKey publicKey;

	private byte[] derSpkac;

	/**
	 * Construct a new SPKAC.
	 *
	 * @param challenge
	 *            Challenge
	 * @param signatureAlgorithm
	 *            Signature algorithm
	 * @param subject
	 *            Subject
	 * @param publicKey
	 *            Public key
	 * @param privateKey
	 *            Private key
	 * @throws SpkacException
	 *             If construction fails
	 */
	public Spkac(String challenge, SignatureType signatureAlgorithm, SpkacSubject subject, PublicKey publicKey,
			PrivateKey privateKey) throws SpkacException {
		this.challenge = challenge;
		this.signatureAlgorithm = signatureAlgorithm;
		this.subject = subject;
		this.publicKey = publicKey;
		this.signature = createSignature(privateKey);
	}

	/**
	 * Load a SPKAC.
	 *
	 * @param is
	 *            Stream to load from
	 * @throws IOException
	 *             If an I/O problem occurs
	 * @throws SpkacMissingPropertyException
	 *             If no subject is present in SPKAC
	 * @throws SpkacException
	 *             If load fails
	 */
	public Spkac(InputStream is) throws IOException, SpkacException {
		Properties properties = readProperties(is);

		if (!properties.containsKey(SPKAC_PROPERTY)) {
			throw new SpkacMissingPropertyException(MessageFormat.format(
					res.getString("SpkacNoIncludeRequiredProperty.exception.message"), SPKAC_PROPERTY));
		}

		subject = getSubject(properties);

		String spkacProperty = properties.getProperty(SPKAC_PROPERTY);

		derSpkac = Base64.decode(spkacProperty);

		decodeSpkac(derSpkac);
	}

	private Properties readProperties(InputStream is) throws IOException {
		try {
			// Properies are defined as name=value pairs where value may be over several lines
			Properties properties = new Properties();

			BufferedReader br = new BufferedReader(new InputStreamReader(is));
			String line;

			String lastName = null;

			while ((line = br.readLine()) != null) {
				line = line.trim();

				int equalsPos = line.indexOf("=");

				if ((equalsPos > 0) && ((equalsPos + 1) < line.length())) {
					String name = line.substring(0, equalsPos);
					String value = line.substring(equalsPos + 1);

					properties.setProperty(name, value);

					lastName = name;
				} else if (lastName != null) {
					properties.setProperty(lastName, String.valueOf(properties.get(lastName)) + line);
				}
			}

			return properties;
		} finally {
			IOUtils.closeQuietly(is);
		}
	}

	private SpkacSubject getSubject(Properties properties) throws SpkacMissingPropertyException {
		String cn = properties.getProperty(CN_PROPERTY);
		String ou = properties.getProperty(OU_PROPERTY);
		String o = properties.getProperty(O_PROPERTY);
		String l = properties.getProperty(L_PROPERTY);
		String st = properties.getProperty(ST_PROPERTY);
		String c = properties.getProperty(C_PROPERTY);

		if ((cn == null) && (ou == null) && (o == null) && (l == null) && (st == null) && (c == null)) {
			throw new SpkacMissingPropertyException(res.getString("SpkacNoIncludeSubjectProperties.exception.message"));
		}

		return new SpkacSubject(cn, ou, o, l, st, c);
	}

	private void decodeSpkac(byte[] der) throws SpkacException {
		try {
			ASN1Sequence signedPublicKeyAndChallenge = ASN1Sequence.getInstance(der);

			ASN1Sequence publicKeyAndChallenge = (ASN1Sequence) signedPublicKeyAndChallenge.getObjectAt(0);
			ASN1Sequence signatureAlgorithm = (ASN1Sequence) signedPublicKeyAndChallenge.getObjectAt(1);
			DERBitString signature = (DERBitString) signedPublicKeyAndChallenge.getObjectAt(2);

			ASN1ObjectIdentifier signatureAlgorithmOid = (ASN1ObjectIdentifier) signatureAlgorithm.getObjectAt(0);

			ASN1Sequence spki = (ASN1Sequence) publicKeyAndChallenge.getObjectAt(0);
			DERIA5String challenge = (DERIA5String) publicKeyAndChallenge.getObjectAt(1);

			ASN1Sequence publicKeyAlgorithm = (ASN1Sequence) spki.getObjectAt(0);
			DERBitString publicKey = (DERBitString) spki.getObjectAt(1);

			ASN1ObjectIdentifier publicKeyAlgorithmOid = (ASN1ObjectIdentifier) publicKeyAlgorithm.getObjectAt(0);
			ASN1Primitive algorithmParameters = publicKeyAlgorithm.getObjectAt(1).toASN1Primitive();

			this.challenge = challenge.getString();
			this.publicKey = decodePublicKeyFromBitString(publicKeyAlgorithmOid, algorithmParameters, publicKey);
			this.signatureAlgorithm = getSignatureAlgorithm(signatureAlgorithmOid);
			this.signature = signature.getBytes();
		} catch (Exception ex) {
			throw new SpkacException(res.getString("NoDecodeSpkac.exception.message"), ex);
		}
	}

	private SignatureType getSignatureAlgorithm(ASN1ObjectIdentifier signatureAlgorithmOid) throws SpkacException {
		SignatureType signatureAlgorithm = SignatureType.resolveOid(signatureAlgorithmOid.getId());

		if (signatureAlgorithm == null) {
			throw new SpkacException(MessageFormat.format(
					res.getString("NoSupportSignatureAlgorithm.exception.message"), signatureAlgorithmOid.getId()));
		}

		return signatureAlgorithm;
	}

	private PublicKey decodePublicKeyFromBitString(ASN1ObjectIdentifier publicKeyAlgorithmOid,
			ASN1Primitive algorithmParameters, DERBitString publicKey) throws SpkacException {
		if (publicKeyAlgorithmOid.getId().equals(RSA.oid())) {
			return decodeRsaPublicKeyFromBitString(publicKey); // Algorithm parameters are ASN1Null and unnecessary
		} else if (publicKeyAlgorithmOid.getId().equals(DSA.oid())) {
			ASN1Sequence dssParams = (ASN1Sequence) algorithmParameters;

			BigInteger p = ((ASN1Integer) dssParams.getObjectAt(0)).getValue();
			BigInteger q = ((ASN1Integer) dssParams.getObjectAt(1)).getValue();
			BigInteger g = ((ASN1Integer) dssParams.getObjectAt(2)).getValue();

			return decodeDsaPublicKeyFromBitString(publicKey, p, q, g);
		} else {
			throw new SpkacException(MessageFormat.format(
					res.getString("NoSupportPublicKeyAlgorithm.exception.message"), publicKeyAlgorithmOid.getId()));

		}
	}

	private RSAPublicKey decodeRsaPublicKeyFromBitString(DERBitString der) throws SpkacException {
		try {
			ASN1Sequence rsaPublicKey = ASN1Sequence.getInstance(der.getBytes());

			BigInteger modulus = ((ASN1Integer) rsaPublicKey.getObjectAt(0)).getValue();
			BigInteger publicExponent = ((ASN1Integer) rsaPublicKey.getObjectAt(1)).getValue();

			KeyFactory keyFact = KeyFactory.getInstance("RSA");

			return (RSAPublicKey) keyFact.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
		} catch (GeneralSecurityException ex) {
			throw new SpkacException(res.getString("NoGenerateRsaPublicKeyFromSpkac.exception.message"), ex);
		} catch (Exception ex) {
			throw new SpkacException(res.getString("NoGenerateRsaPublicKeyFromSpkac.exception.message"), ex);
		}
	}

	private DERBitString encodePublicKeyAsBitString(PublicKey publicKey) throws SpkacException {
		byte[] encodedPublicKey;

		if (publicKey instanceof RSAPublicKey) {
			encodedPublicKey = encodeRsaPublicKeyAsBitString((RSAPublicKey) publicKey);
		} else {
			encodedPublicKey = encodeDsaPublicKeyAsBitString((DSAPublicKey) publicKey);
		}

		return new DERBitString(encodedPublicKey);
	}

	private byte[] encodeRsaPublicKeyAsBitString(RSAPublicKey rsaPublicKey) throws SpkacException {
		try {
			ASN1EncodableVector vec = new ASN1EncodableVector ();
			vec.add(new ASN1Integer(rsaPublicKey.getModulus()));
			vec.add(new ASN1Integer(rsaPublicKey.getPublicExponent()));
			DERSequence derSequence = new DERSequence(vec);
			return derSequence.getEncoded(ASN1Encoding.DER);
		} catch (Exception ex) {
			throw new SpkacException(res.getString("NoEncodeRsaPublicKey.exception.message"), ex);
		}
	}

	private DSAPublicKey decodeDsaPublicKeyFromBitString(DERBitString der, BigInteger p, BigInteger q, BigInteger g)
			throws SpkacException {
		try {
			BigInteger y = ASN1Integer.getInstance(der.getBytes()).getValue();

			KeyFactory keyFact = KeyFactory.getInstance("DSA");

			return (DSAPublicKey) keyFact.generatePublic(new DSAPublicKeySpec(y, p, q, g));
		} catch (GeneralSecurityException ex) {
			throw new SpkacException(res.getString("NoGenerateDsaPublicKeyFromSpkac.exception.message"), ex);
		} catch (Exception ex) {
			throw new SpkacException(res.getString("NoGenerateDsaPublicKeyFromSpkac.exception.message"), ex);
		}
	}

	private byte[] encodeDsaPublicKeyAsBitString(DSAPublicKey dsaPublicKey) throws SpkacException {
		try {
			ASN1Integer publicKey = new ASN1Integer(dsaPublicKey.getY());

			return publicKey.getEncoded(ASN1Encoding.DER);
		} catch (Exception ex) {
			throw new SpkacException(res.getString("NoEncodeDsaPublicKey.exception.message"), ex);
		}
	}

	/**
	 * Output SPKAC.
	 *
	 * @param os
	 *            Output stream
	 * @throws IOException
	 *             If an I/O problem occurs
	 * @throws SpkacException
	 *             If output fails
	 */
	public void output(OutputStream os) throws IOException, SpkacException {
		OutputStreamWriter osw = null;

		try {
			osw = new OutputStreamWriter(os);

			outputProperty(osw, SPKAC_PROPERTY,
					new String(Base64.encode(createSignedPublicKeyAndChallenge().getEncoded(ASN1Encoding.DER))));
			outputProperty(osw, CN_PROPERTY, subject.getCN());
			outputProperty(osw, OU_PROPERTY, subject.getOU());
			outputProperty(osw, O_PROPERTY, subject.getO());
			outputProperty(osw, L_PROPERTY, subject.getL());
			outputProperty(osw, ST_PROPERTY, subject.getST());
			outputProperty(osw, C_PROPERTY, subject.getC());
		} catch (IOException ex) {
			throw new SpkacException(res.getString("NoOutputSpkac.exception.message"), ex);
		} finally {
			IOUtils.closeQuietly(osw);
		}
	}

	private void outputProperty(Writer w, String name, String value) throws IOException {
		if (value != null) {
			w.write(name + "=" + value + NEWLINE);
		}
	}

	/**
	 * Verify SPKAC including the challenge.
	 *
	 * @param challenge
	 *            Challenge
	 * @return True if verified successfully, false otherwise
	 * @throws SpkacException
	 *             If verification fails
	 */
	public boolean verify(String challenge) throws SpkacException {
		if (!challenge.equals(getChallenge())) {
			return false;
		}

		return verify();
	}

	/**
	 * Verify SPKAC.
	 *
	 * @return True if verified successfully, false otherwise
	 * @throws SpkacException
	 *             If verification fails
	 */
	public boolean verify() throws SpkacException {
		try {
			byte[] publicKeyAndChallenge = createPublicKeyAndChallengeForSigning();

			Signature sig = Signature.getInstance(getSignatureAlgorithm().jce());
			sig.initVerify(getPublicKey());
			sig.update(publicKeyAndChallenge);

			return sig.verify(signature);
		} catch (GeneralSecurityException ex) {
			throw new SpkacException(res.getString("NoVerifySpkacSignature.exception.message"), ex);

		}
	}

	private byte[] createSignature(PrivateKey privateKey) throws SpkacException {
		try {
			byte[] publicKeyAndChallenge = createPublicKeyAndChallengeForSigning();

			Signature sig = Signature.getInstance(getSignatureAlgorithm().jce());
			sig.initSign(privateKey);
			sig.update(publicKeyAndChallenge);

			return sig.sign();
		} catch (GeneralSecurityException ex) {
			throw new SpkacException(res.getString("NoCreateSpkacSignature.exception.message"), ex);
		}
	}

	private ASN1Sequence createSignedPublicKeyAndChallenge() throws SpkacException {
		ASN1EncodableVector vec = new ASN1EncodableVector ();
		vec.add(new ASN1ObjectIdentifier(getSignatureAlgorithm().oid()));
		vec.add(DERNull.INSTANCE);
		DERSequence signatureAlgorithm = new DERSequence(vec);

		vec = new ASN1EncodableVector ();
		vec.add(createPublicKeyAndChallenge());
		vec.add(signatureAlgorithm);
		vec.add(new DERBitString(signature));

		return new DERSequence(vec);
	}

	private ASN1Sequence createPublicKeyAndChallenge() throws SpkacException {
		ASN1EncodableVector publicKeyAlgorithm = new ASN1EncodableVector();
		publicKeyAlgorithm.add(new ASN1ObjectIdentifier(getPublicKeyAlg().oid()));

		if (getPublicKey() instanceof RSAPublicKey) {
			publicKeyAlgorithm.add(DERNull.INSTANCE);
		} else {
			DSAParams dsaParams = ((DSAPublicKey) getPublicKey()).getParams();

			ASN1EncodableVector dssParams = new ASN1EncodableVector();
			dssParams.add(new ASN1Integer(dsaParams.getP()));
			dssParams.add(new ASN1Integer(dsaParams.getQ()));
			dssParams.add(new ASN1Integer(dsaParams.getG()));

			publicKeyAlgorithm.add(new DERSequence(dssParams));
		}

		ASN1EncodableVector spki = new ASN1EncodableVector();
		spki.add(new DERSequence(publicKeyAlgorithm));
		spki.add(encodePublicKeyAsBitString(getPublicKey()));

		ASN1EncodableVector publicKeyAndChallenge = new ASN1EncodableVector();
		publicKeyAndChallenge.add(new DERSequence(spki));
		publicKeyAndChallenge.add(new DERIA5String(getChallenge()));
		return new DERSequence(publicKeyAndChallenge);
	}

	private byte[] createPublicKeyAndChallengeForSigning() throws SpkacException {
		try {
			return new DERBitString(createPublicKeyAndChallenge().getEncoded(ASN1Encoding.DER)).getBytes();
		} catch (Exception ex) {
			throw new SpkacException(res.getString("NoGetPublicKeyAndChallengeForSignature.exception.message"), ex);
		}
	}

	/**
	 * Get challenge.
	 *
	 * @return Challenge
	 */
	public String getChallenge() {
		return challenge;
	}

	/**
	 * Get subject.
	 *
	 * @return Subject
	 */
	public SpkacSubject getSubject() {
		return subject;
	}

	/**
	 * Get signature algorithm.
	 *
	 * @return Signature algorithm
	 */
	public SignatureType getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	/**
	 * Get public key.
	 *
	 * @return Public key
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Get public key algorithm.
	 *
	 * @return Public key algorithm
	 */
	public KeyPairType getPublicKeyAlg() {
		if (getPublicKey() instanceof RSAPublicKey) {
			return RSA;
		} else {
			return DSA;
		}
	}

	public byte[] getEncoded() {
		return derSpkac;
	}

	@Override
	public String toString() {
		return "challenge=" + getChallenge() + ", signatureAlgorithm=" + signatureAlgorithm + ", signature="
				+ HexUtil.getHexString(signature) + ", subject=" + getSubject() + ", publicKey=" + publicKey;
	}
}
