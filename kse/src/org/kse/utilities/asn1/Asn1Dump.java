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
package org.kse.utilities.asn1;

import java.io.IOException;
import java.io.LineNumberReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNumericString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.DERVisibleString;
import org.kse.crypto.x509.X509Ext;
import org.kse.utilities.io.HexUtil;
import org.kse.utilities.io.IndentChar;
import org.kse.utilities.io.IndentSequence;
import org.kse.utilities.oid.ObjectIdUtil;

/**
 * Utility class to produce string dumps of the contents of ASN.1 objects.
 *
 */
public class Asn1Dump {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/utilities/asn1/resources");
	private IndentSequence indentSequence;
	private int indentLevel = -1;
	private static final String NEWLINE = "\n";

	/**
	 * Construct Asn1Dump that uses 4 spaces as its indent sequence.
	 */
	public Asn1Dump() {
		indentSequence = new IndentSequence(IndentChar.SPACE, 4);
	}

	/**
	 * Construct Asn1Dump.
	 *
	 * @param indentSequence
	 *            Indent sequence
	 */
	public Asn1Dump(IndentSequence indentSequence) {
		this.indentSequence = indentSequence;
	}

	/**
	 * Get dump of the supplied X.509 certificate.
	 *
	 * @param certificate
	 *            X.509 certificate
	 * @return Dump of certificate
	 * @throws Asn1Exception
	 *             A problem was encountered getting the ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public String dump(X509Certificate certificate) throws Asn1Exception, IOException {
		try {
			return dump(certificate.getEncoded());
		} catch (IOException ex) {
			throw new Asn1Exception(res.getString("NoAsn1DumpObject.exception.message"), ex);
		} catch (CertificateEncodingException ex) {
			throw new Asn1Exception(res.getString("NoAsn1DumpObject.exception.message"), ex);
		}
	}

	/**
	 * Get dump of the supplied X.509 CRL.
	 *
	 * @param crl
	 *            X.509 CRL
	 * @return Dump of CRL
	 * @throws Asn1Exception
	 *             A problem was encountered getting the ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public String dump(X509CRL crl) throws Asn1Exception, IOException {
		try {
			return dump(crl.getEncoded());
		} catch (IOException ex) {
			throw new Asn1Exception(res.getString("NoAsn1DumpObject.exception.message"), ex);
		} catch (CRLException ex) {
			throw new Asn1Exception(res.getString("NoAsn1DumpObject.exception.message"), ex);
		}
	}

	/**
	 * Get dump of the supplied X.509 extension.
	 *
	 * @param extension
	 *            X.509 extension
	 * @return Dump of extension
	 * @throws Asn1Exception
	 *             A problem was encountered getting the ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public String dump(X509Ext extension) throws Asn1Exception, IOException {
		try {
			ASN1OctetString octetString = ASN1OctetString.getInstance(extension.getValue());
			byte[] octets = octetString.getOctets();

			return dump(octets);
		} catch (IOException ex) {
			throw new Asn1Exception(res.getString("NoAsn1DumpObject.exception.message"), ex);
		}
	}

	/**
	 * Get dump of the supplied private key.
	 *
	 * @param privateKey
	 *            Private key
	 * @return Dump of private key
	 * @throws Asn1Exception
	 *             A problem was encountered getting the ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public String dump(PrivateKey privateKey) throws Asn1Exception, IOException {
		return dump(privateKey.getEncoded());
	}

	/**
	 * Get dump of the supplied public key.
	 *
	 * @param publicKey
	 *            Public key
	 * @return Dump of private key
	 * @throws Asn1Exception
	 *             A problem was encountered getting the ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public String dump(PublicKey publicKey) throws Asn1Exception, IOException {
		return dump(publicKey.getEncoded());
	}

	/**
	 * Get dump of the supplied DER encoded ASN.1 object.
	 *
	 * @param der
	 *            DER encoded ASN.1 object
	 * @return Dump of object
	 * @throws Asn1Exception
	 *             A problem was encountered getting the ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public String dump(byte[] der) throws Asn1Exception, IOException {
		try {
			ASN1Primitive derObject = ASN1Primitive.fromByteArray(der);

			// if size of re-encoded DER primitive differs from input data there must be sth wrong
			if (derObject.getEncoded().length < der.length) {
				throw new Asn1Exception(res.getString("NoAsn1DumpObject.exception.message"));
			}

			return dump(derObject);
		} catch (IOException ex) {
			throw new Asn1Exception(res.getString("NoAsn1DumpObject.exception.message"), ex);
		}
	}

	/**
	 * Get dump of the supplied ASN.1 object.
	 *
	 * @param asn1Object
	 *            ASN.1 object
	 * @return Dump of object
	 * @throws Asn1Exception
	 *             A problem was encountered getting the ASN.1 dump
	 * @throws IOException
	 *             If an I/O problem occurred
	 */
	public String dump(ASN1Primitive asn1Object) throws Asn1Exception, IOException {
		// Get dump of the supplied ASN.1 object incrementing the indent level of the output
		try {
			indentLevel++;

			if (asn1Object instanceof DERBitString) { // special case of ASN1String
				return dumpBitString((DERBitString) asn1Object);
			} else if (asn1Object instanceof ASN1String) {
				return dumpString((ASN1String) asn1Object);
			} else if (asn1Object instanceof ASN1UTCTime) {
				return dumpUTCTime((ASN1UTCTime) asn1Object);
			} else if (asn1Object instanceof ASN1GeneralizedTime) {
				return dumpGeneralizedTime((ASN1GeneralizedTime) asn1Object);
			} else if (asn1Object instanceof ASN1Sequence ||
					asn1Object instanceof ASN1Set ) {
				return dumpSetOrSequence(asn1Object);
			} else if (asn1Object instanceof ASN1TaggedObject) {
				return dumpTaggedObject((ASN1TaggedObject) asn1Object);
			} else if (asn1Object instanceof ASN1Boolean) {
				return dumpBoolean((ASN1Boolean) asn1Object);
			} else if (asn1Object instanceof ASN1Enumerated) {
				return dumpEnumerated((ASN1Enumerated) asn1Object);
			} else if (asn1Object instanceof ASN1Integer) {
				return dumpInteger((ASN1Integer) asn1Object);
			} else if (asn1Object instanceof ASN1Null) {
				return dumpNull((ASN1Null) asn1Object);
			} else if (asn1Object instanceof ASN1ObjectIdentifier) {
				return dumpObjectIdentifier((ASN1ObjectIdentifier) asn1Object);
			} else if (asn1Object instanceof ASN1OctetString) {
				return dumpOctetString((ASN1OctetString) asn1Object);
			} else {
				throw new Asn1Exception("Unknown ASN.1 object: " + asn1Object.toString());
			}
		} finally {
			if (true) {
				indentLevel--;
			}
		}
	}

	private String dumpTaggedObject(ASN1TaggedObject o) throws Asn1Exception, IOException {

		StringBuilder sb = new StringBuilder();

		sb.append(indentSequence.toString(indentLevel));
		if (o instanceof BERTaggedObject) {
			sb.append("BER TAGGED [");
		} else {
			sb.append("TAGGED [");
		}
		sb.append(Integer.toString(o.getTagNo()));
		sb.append(']');

		if (!o.isExplicit()) {
			sb.append(" IMPLICIT ");
		}
		sb.append(":");
		sb.append(NEWLINE);

		if (o.isEmpty()) {
			sb.append("EMPTY");
		} else {
			sb.append(dump(o.getObject()));
		}

		return sb.toString();
	}

	private String dumpOctetString(ASN1OctetString asn1OctetString) throws IOException {
		StringBuilder sb = new StringBuilder();
		byte[] bytes = asn1OctetString.getOctets();

		sb.append(indentSequence.toString(indentLevel));
		sb.append("OCTET STRING");
		try {
			String encapsulated = dump(bytes);
			sb.append(", encapsulates:");
			sb.append(NEWLINE);
			sb.append(encapsulated);
		} catch (Exception e) {
			sb.append("=");
			if (bytes.length < 8) {
				sb.append(HexUtil.getHexString(bytes));
			} else {
				sb.append(NEWLINE);
				sb.append(dumpHexClear(bytes));
			}
		}
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpBitString(DERBitString asn1BitString) throws IOException {
		StringBuilder sb = new StringBuilder();
		byte[] bytes = asn1BitString.getBytes();

		sb.append(indentSequence.toString(indentLevel));
		sb.append("BIT STRING");
		try {
			String dump = dump(bytes);
			sb.append(", encapsulates:");
			sb.append(NEWLINE);
			sb.append(dump);
		} catch (Exception e) {
			sb.append("=");

			// print short bit strings as string of bits and long ones as hex dump
			if (bytes.length < 8) {
				sb.append(new BigInteger(1, bytes).toString(2));
			} else {
				sb.append(NEWLINE);
				sb.append(dumpHexClear(bytes));
			}
		}
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpObjectIdentifier(ASN1ObjectIdentifier asn1ObjectIdentifier) {
		StringBuilder sb = new StringBuilder();

		sb.append(indentSequence.toString(indentLevel));
		sb.append("OBJECT IDENTIFIER=");
		sb.append(ObjectIdUtil.toString(asn1ObjectIdentifier));
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpNull(ASN1Null asn1Null) {
		StringBuilder sb = new StringBuilder();

		sb.append(indentSequence.toString(indentLevel));
		sb.append("NULL");
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpInteger(ASN1Integer asn1Integer) throws IOException {
		StringBuilder sb = new StringBuilder();
		BigInteger value = asn1Integer.getValue();

		sb.append(indentSequence.toString(indentLevel));
		sb.append("INTEGER=");
		// is big int value small enough to be displayed as a number?
		if (value.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) == -1) {
			sb.append(value.toString(10));
			if (value.longValue() >= 10) {
				sb.append(" (0x").append(value.toString(16)).append(")");
			}
		} else {
			// else print as byte array
			sb.append(NEWLINE);
			sb.append(dumpHexClear(value.toByteArray()));
		}
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpEnumerated(ASN1Enumerated asn1Enumerated) {
		StringBuilder sb = new StringBuilder();

		sb.append(indentSequence.toString(indentLevel));
		sb.append("ENUMERATED=");
		sb.append(asn1Enumerated.getValue());
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpBoolean(ASN1Boolean asn1Boolean) {
		StringBuilder sb = new StringBuilder();

		sb.append(indentSequence.toString(indentLevel));
		sb.append("BOOLEAN=");
		sb.append(asn1Boolean.isTrue());
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpSetOrSequence(ASN1Encodable asn1ConstructedType) throws Asn1Exception, IOException {
		StringBuilder sb = new StringBuilder();

		sb.append(indentSequence.toString(indentLevel));

		Enumeration<?> components;

		// Sequence or Set?
		if (asn1ConstructedType instanceof ASN1Sequence) {
			sb.append("SEQUENCE");
			ASN1Sequence sequence = (ASN1Sequence) asn1ConstructedType;
			components = sequence.getObjects();
		} else {
			// == SET
			sb.append("SET");
			ASN1Set set = (ASN1Set) asn1ConstructedType;
			components = set.getObjects();
		}

		sb.append(NEWLINE);

		sb.append(indentSequence.toString(indentLevel));
		sb.append("{");
		sb.append(NEWLINE);

		while (components.hasMoreElements()) {
			ASN1Primitive component = (ASN1Primitive) components.nextElement();
			sb.append(dump(component));
		}

		sb.append(indentSequence.toString(indentLevel));

		sb.append("}");
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpUTCTime(ASN1UTCTime asn1Time) {
		StringBuilder sb = new StringBuilder();

		sb.append(indentSequence.toString(indentLevel));
		sb.append("UTC TIME=");

		// UTCTime, note does not support ms precision hence the different date format
		Date date;
		try {
			date = asn1Time.getDate();
		} catch (ParseException e) {
			throw new RuntimeException("Cannot parse utc time");
		}
		String formattedDate = new SimpleDateFormat("dd/MMM/yyyy HH:mm:ss z").format(date);

		sb.append(formattedDate);
		sb.append(" (");
		sb.append(asn1Time.getTime());
		sb.append(")");
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpGeneralizedTime(ASN1GeneralizedTime asn1Time) {
		StringBuilder sb = new StringBuilder();

		sb.append(indentSequence.toString(indentLevel));
		sb.append("GENERALIZED TIME=");

		Date date;
		try {
			date = asn1Time.getDate();
		} catch (ParseException e) {
			throw new RuntimeException("Cannot parse generalized time");
		}
		String formattedDate = new SimpleDateFormat("dd/MMM/yyyy HH:mm:ss.SSS z").format(date);

		sb.append(formattedDate);
		sb.append(" (");
		sb.append(asn1Time.getTime());
		sb.append(")");
		sb.append(NEWLINE);

		return sb.toString();
	}

	private String dumpString(ASN1String asn1String) {
		StringBuilder sb = new StringBuilder();

		sb.append(indentSequence.toString(indentLevel));

		if (asn1String instanceof DERBMPString) {
			sb.append("BMP STRING=");
		} else if (asn1String instanceof DERGeneralString) {
			sb.append("GENERAL STRING=");
		} else if (asn1String instanceof DERIA5String) {
			sb.append("IA5 STRING=");
		} else if (asn1String instanceof DERNumericString) {
			sb.append("NUMERIC STRING=");
		} else if (asn1String instanceof DERPrintableString) {
			sb.append("PRINTABLE STRING=");
		} else if (asn1String instanceof DERT61String) {
			sb.append("TELETEX STRING=");
		} else if (asn1String instanceof DERUniversalString) {
			sb.append("UNIVERSAL STRING=");
		} else if (asn1String instanceof DERUTF8String) {
			sb.append("UTF8 STRING=");
		} else if (asn1String instanceof DERVisibleString) {
			sb.append("VISIBLE STRING=");
		} else {
			sb.append("UNKNOWN STRING=");
		}

		sb.append("'");
		sb.append(asn1String.getString());
		sb.append("'");
		sb.append(NEWLINE);

		return sb.toString();
	}


	private String dumpHexClear(byte[] der) throws IOException {
		try {
			indentLevel++;

			// Get hex/clear dump of value
			String hexClearDump = HexUtil.getHexClearDump(der);

			// Put indent at the start of each line of the dump
			LineNumberReader lnr = new LineNumberReader(new StringReader(hexClearDump));

			StringBuilder sb = new StringBuilder();

			String line = null;
			boolean firstLine = true;

			while ((line = lnr.readLine()) != null) {
				if (firstLine) {
					firstLine = false;
				} else {
					sb.append(NEWLINE);
				}

				sb.append(indentSequence.toString(indentLevel));
				sb.append(line);
			}

			lnr.close();
			return sb.toString();
		} finally {
			indentLevel--;
		}
	}
}
