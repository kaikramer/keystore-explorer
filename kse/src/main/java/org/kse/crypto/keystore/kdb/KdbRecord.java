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
package org.kse.crypto.keystore.kdb;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERVisibleString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.gui.passwordmanager.Password;

/**
 * One record in a CMS key database: a labelled certificate, optionally with an encrypted
 * private key. Outer ASN.1:
 * {@code SEQUENCE { INTEGER version, [1]{cert} | [2]{SEQ{cert, EncryptedPrivateKeyInfo}},
 * VisibleString label, BIT STRING flags }}.
 */
public final class KdbRecord {

    static final int TYPE_KEY = 1;       // certificate (optionally with key)
    static final int TYPE_KEYPAIR = 2;   // certificate + key

    /** Private keys are wrapped as PBES2 (PBKDF2-HMAC-SHA384 + AES-256-CBC), the scheme gskcapicmd uses. */
    private static final AlgorithmIdentifier PBKDF2_PRF_SHA384 =
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA384, DERNull.INSTANCE);

    private final String label;
    private final int recordType;
    private int recordNumber;
    private final byte[] recordDer;
    private final byte[] trailing;

    private final List<X509Certificate> certificates = new ArrayList<>();
    private byte[] encryptedKeyDer;
    private byte[] csrDer;       // PKCS#10 request DER (request records only)
    private boolean secretKey;   // true for secret-key records

    KdbRecord(String label, int recordType, int recordNumber, byte[] recordDer, byte[] trailing) {
        this.label = label;
        this.recordType = recordType;
        this.recordNumber = recordNumber;
        this.recordDer = recordDer;
        this.trailing = trailing;
        parse();
    }

    public String label() { return label; }
    public boolean hasPrivateKey() { return encryptedKeyDer != null; }
    public List<X509Certificate> certificates() { return certificates; }
    public X509Certificate certificate() { return certificates.isEmpty() ? null : certificates.get(0); }
    public byte[] der() { return recordDer; }
    public int recordType() { return recordType; }
    public byte[] encryptedKeyDer() { return encryptedKeyDer; }
    public byte[] csrDer() { return csrDer; }
    public boolean isRequest() { return csrDer != null; }
    public boolean isSecretKey() { return secretKey; }
    void setRecordNumber(int n) { this.recordNumber = n; }

    // --------------------------------------------------------------- builders

    /** Builds a trusted-certificate record (no private key). */
    public static KdbRecord caRecord(String label, X509Certificate cert) throws Exception {
        byte[] der = record(taggedCert(1, cert.getEncoded()), label, trustedCaFlag());
        return new KdbRecord(label, TYPE_KEY, 0, der, trailingFor(cert));
    }

    /** Builds a personal record: certificate + PBES2-encrypted private key. */
    public static KdbRecord personalRecord(String label, X509Certificate cert,
                                           byte[] encryptedKeyDer) throws Exception {
        ASN1Sequence inner = new DERSequence(new ASN1Encodable[] { der(cert.getEncoded()), der(encryptedKeyDer) });
        byte[] der = record(new DERTaggedObject(true, 2, inner), label, personalFlag());
        // The record-type field is 1 ("key record") for both CA and key-pair records;
        // the key-pair-ness is carried by the [2] DER tag, not this field.
        return new KdbRecord(label, TYPE_KEY, 0, der, trailingFor(cert));
    }

    /** Builds a certificate-request record for the .rdb: [0]{ SEQ{ CSR, EncryptedPrivateKeyInfo } }. */
    public static KdbRecord requestRecord(String label, byte[] csrDer, byte[] encryptedKeyDer) {
        ASN1Sequence inner = new DERSequence(new ASN1Encodable[] { der(csrDer), der(encryptedKeyDer) });
        byte[] der = record(new DERTaggedObject(true, 0, inner), label, trustedCaFlag());
        return new KdbRecord(label, TYPE_KEY, 0, der, new byte[]{0, 0, 0, 0});
    }

    /** Builds a secret-key record: [3]{ EncryptedPrivateKeyInfo wrapping the raw key }. */
    public static KdbRecord secretKeyRecord(String label, byte[] encryptedKeyDer) {
        byte[] der = record(new DERTaggedObject(true, 3, der(encryptedKeyDer)), label, trustedCaFlag());
        return new KdbRecord(label, TYPE_KEY, 0, der, new byte[]{0, 0, 0, 0});
    }

    /** Encrypts a private key into the PBES2 EncryptedPrivateKeyInfo the CMS key database stores. */
    public static byte[] encryptPrivateKey(PrivateKey key, char[] password) throws CryptoException {
        try {
            OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                    .setProvider(KSE.BC)
                    .setPRF(PBKDF2_PRF_SHA384)
                    .build(password);
            return new PKCS8EncryptedPrivateKeyInfoBuilder(key.getEncoded()).build(encryptor).getEncoded();
        } catch (Exception e) {
            throw new CryptoException("Could not encrypt private key", e);
        }
    }

    /** Wraps the outer record SEQUENCE: { INTEGER version, content, VisibleString label, BIT STRING flags }. */
    private static byte[] record(ASN1Encodable content, String label, ASN1BitString flags) {
        ASN1Sequence seq = new DERSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            content,
            new DERVisibleString(label),
            flags
        });
        return derBytes(seq);
    }

    private static DERTaggedObject taggedCert(int tagNo, byte[] certDer) {
        return new DERTaggedObject(true, tagNo, der(certDer));
    }

    private static ASN1BitString trustedCaFlag() { return new DERBitString(new byte[]{(byte) 0x80}, 7); }
    private static ASN1BitString personalFlag()  { return new DERBitString(new byte[]{(byte) 0xC0}, 6); }

    /** trailing: flags(0) | len20 | SHA1(SPKI) | len20 | SHA1(cert) */
    private static byte[] trailingFor(X509Certificate cert) throws Exception {
        byte[] spki = cert.getPublicKey().getEncoded();
        byte[] v1 = sha1(spki);
        byte[] v2 = sha1(cert.getEncoded());
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        put(o, new byte[4]);            // flags
        put(o, be(20)); put(o, v1);
        put(o, be(20)); put(o, v2);
        return o.toByteArray();
    }

    /** The number of bytes this record needs in a slot (before zero padding). */
    int slotBytesNeeded() {
        return slotBody().length;
    }

    /** Serialises this record into a fixed-size slot. */
    byte[] toSlot(int slotSize) {
        byte[] body = slotBody();
        if (body.length > slotSize) {
            throw new IllegalStateException("record '" + label + "' (" + body.length
                + " bytes) exceeds slot size " + slotSize);
        }
        byte[] slot = new byte[slotSize];
        System.arraycopy(body, 0, slot, 0, body.length);
        return slot;
    }

    private byte[] slotBody() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        put(o, be(recordType));
        put(o, be(recordNumber));
        put(o, be(recordDer.length));
        put(o, recordDer);
        byte[] lbl = label.getBytes(StandardCharsets.UTF_8);
        put(o, be(lbl.length + 1));     // length includes NUL
        put(o, lbl);
        o.write(0);
        put(o, trailing);
        return o.toByteArray();
    }

    // ----------------------------------------------------------------- parse

    private void parse() {
        try {
            ASN1Sequence root = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(recordDer));
            for (ASN1Encodable element : root) {
                ASN1Primitive node = element.toASN1Primitive();
                if (node instanceof ASN1TaggedObject) {
                    ASN1TaggedObject tagged = (ASN1TaggedObject) node;
                    if (tagged.getTagNo() == 0) {                  // [0] request
                        ASN1Sequence inner = ASN1Sequence.getInstance(tagged.getBaseObject());
                        csrDer = derBytes(inner.getObjectAt(0));
                        if (inner.size() > 1) {
                            encryptedKeyDer = derBytes(inner.getObjectAt(1));
                        }
                        return;
                    } else if (tagged.getTagNo() == 3) {           // [3] secret key
                        secretKey = true;
                        encryptedKeyDer = derBytes(tagged.getBaseObject());
                        return;
                    }
                }
            }
            collect(root);                                         // [1] cert / [2] key-pair
        } catch (RuntimeException | java.io.IOException ignore) {}
    }

    private void collect(ASN1Primitive node) {
        if (node instanceof ASN1Sequence) {
            ASN1Sequence seq = (ASN1Sequence) node;
            if (encryptedKeyDer == null && isEncryptedPrivateKeyInfo(seq)) {
                encryptedKeyDer = derBytes(seq);
                return;
            }
            X509Certificate cert = tryCert(derBytes(seq));
            if (cert != null) { certificates.add(cert); return; }
            for (ASN1Encodable child : seq) {
                collect(child.toASN1Primitive());
            }
        } else if (node instanceof ASN1TaggedObject) {
            collect(((ASN1TaggedObject) node).getBaseObject().toASN1Primitive());
        }
    }

    /** SEQ { SEQ { OID (PBE), ... }, OCTET STRING } — an EncryptedPrivateKeyInfo. */
    private static boolean isEncryptedPrivateKeyInfo(ASN1Sequence seq) {
        if (seq.size() != 2 || !(seq.getObjectAt(0).toASN1Primitive() instanceof ASN1Sequence)
                || !(seq.getObjectAt(1).toASN1Primitive() instanceof ASN1OctetString)) {
            return false;
        }
        ASN1Sequence algId = (ASN1Sequence) seq.getObjectAt(0).toASN1Primitive();
        return algId.size() >= 1 && algId.getObjectAt(0).toASN1Primitive() instanceof ASN1ObjectIdentifier
                && isPbe(((ASN1ObjectIdentifier) algId.getObjectAt(0).toASN1Primitive()).getId());
    }

    private static boolean isPbe(String oid) {
        // 1.2.840.113549.1.5.* = PKCS#5 PBES; 1.2.840.113549.1.12.1.* = PKCS#12 PBE
        return oid.startsWith("1.2.840.113549.1.5") || oid.startsWith("1.2.840.113549.1.12.1");
    }

    private static X509Certificate tryCert(byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) { return null; }
    }

    public PrivateKey privateKey(char[] password) throws Exception {
        if (encryptedKeyDer == null) throw new IllegalStateException("record '" + label + "' has no private key");
        PrivateKey key = Pkcs8Util.loadEncrypted(encryptedKeyDer, new Password(password));
        // BouncyCastle labels EC keys "ECDSA"; re-key off the certificate so this key store reports
        // the same algorithm name ("EC", "RSA", ...) as the JDK-backed key stores do.
        if (certificate() != null) {
            String algorithm = certificate().getPublicKey().getAlgorithm();
            if (!algorithm.equals(key.getAlgorithm())) {
                key = KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
        }
        return key;
    }

    // --------------------------------------------------------------- ASN.1 helpers

    /** Reads already-encoded DER bytes back into an ASN.1 object for re-embedding. */
    private static ASN1Primitive der(byte[] derEncoded) {
        try {
            return ASN1Primitive.fromByteArray(derEncoded);
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("invalid DER", e);
        }
    }

    private static byte[] derBytes(ASN1Encodable obj) {
        try {
            return obj.toASN1Primitive().getEncoded("DER");
        } catch (java.io.IOException e) {
            throw new IllegalStateException("could not DER-encode ASN.1 object", e);
        }
    }

    /** Appends a whole byte[] to a buffer (ByteArrayOutputStream.write(byte[],int,int) is exception-free). */
    private static void put(ByteArrayOutputStream o, byte[] b) { o.write(b, 0, b.length); }

    private static byte[] sha1(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-1").digest(b); }
    private static byte[] be(int v) {
        return new byte[]{(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }
}
