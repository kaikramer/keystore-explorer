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
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.kse.crypto.keystore.kdb.asn1.Der;

/**
 * One record in an IBM CMS key database: a labelled certificate, optionally with an encrypted
 * private key. Outer ASN.1:
 * {@code SEQUENCE { INTEGER version, [1]{cert} | [2]{SEQ{cert, EncryptedPrivateKeyInfo}},
 * VisibleString label, BIT STRING flags }}.
 */
public final class KdbRecord {

    static final int TYPE_KEY = 1;       // certificate (optionally with key)
    static final int TYPE_KEYPAIR = 2;   // certificate + key

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
        byte[] certDer = cert.getEncoded();
        byte[] der = Der.sequence(
            Der.integer(1),
            Der.encode(0xA1, certDer),
            Der.encode(0x1A, label.getBytes(StandardCharsets.UTF_8)),
            Der.encode(0x03, new byte[]{0x07, (byte) 0x80}));          // trusted CA flag
        return new KdbRecord(label, TYPE_KEY, 0, der, trailingFor(cert));
    }

    /** Builds a personal record: certificate + PBES2-encrypted private key. */
    public static KdbRecord personalRecord(String label, X509Certificate cert,
                                           byte[] encryptedKeyDer) throws Exception {
        byte[] inner = Der.sequence(cert.getEncoded(), encryptedKeyDer);
        byte[] der = Der.sequence(
            Der.integer(1),
            Der.encode(0xA2, inner),
            Der.encode(0x1A, label.getBytes(StandardCharsets.UTF_8)),
            Der.encode(0x03, new byte[]{0x06, (byte) 0xC0}));          // personal flag
        // The record-type field is 1 ("key record") for both CA and key-pair records;
        // the key-pair-ness is carried by the [2] DER tag, not this field.
        return new KdbRecord(label, TYPE_KEY, 0, der, trailingFor(cert));
    }

    /** Builds a certificate-request record for the .rdb: [0]{ SEQ{ CSR, EncryptedPrivateKeyInfo } }. */
    public static KdbRecord requestRecord(String label, byte[] csrDer, byte[] encryptedKeyDer) {
        byte[] inner = Der.sequence(csrDer, encryptedKeyDer);
        byte[] der = Der.sequence(
            Der.integer(1),
            Der.encode(0xA0, inner),
            Der.encode(0x1A, label.getBytes(StandardCharsets.UTF_8)),
            Der.encode(0x03, new byte[]{0x07, (byte) 0x80}));
        return new KdbRecord(label, TYPE_KEY, 0, der, new byte[]{0, 0, 0, 0});
    }

    /** Builds a secret-key record: [3]{ EncryptedPrivateKeyInfo wrapping the raw key }. */
    public static KdbRecord secretKeyRecord(String label, byte[] encryptedKeyDer) {
        byte[] der = Der.sequence(
            Der.integer(1),
            Der.encode(0xA3, encryptedKeyDer),
            Der.encode(0x1A, label.getBytes(StandardCharsets.UTF_8)),
            Der.encode(0x03, new byte[]{0x07, (byte) 0x80}));
        return new KdbRecord(label, TYPE_KEY, 0, der, new byte[]{0, 0, 0, 0});
    }

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
            Der.Node root = Der.parse(recordDer);
            for (Der.Node child : root.children()) {
                if (child.tag == 0xA0) {                       // [0] request
                    List<Der.Node> inner = child.children().get(0).children();
                    csrDer = inner.get(0).der();
                    if (inner.size() > 1) encryptedKeyDer = inner.get(1).der();
                    return;
                } else if (child.tag == 0xA3) {                // [3] secret key
                    secretKey = true;
                    encryptedKeyDer = child.children().isEmpty() ? null : child.children().get(0).der();
                    return;
                }
            }
            collect(root);                                     // [1] cert / [2] key-pair
        } catch (RuntimeException ignore) {}
    }

    private void collect(Der.Node node) {
        if (node.tag == 0x30) {
            List<Der.Node> ch = node.children();
            if (encryptedKeyDer == null && ch.size() == 2
                    && ch.get(0).tag == 0x30 && ch.get(1).tag == 0x04
                    && !ch.get(0).children().isEmpty()
                    && ch.get(0).children().get(0).tag == 0x06
                    && isPbe(ch.get(0).children().get(0).content())) {
                encryptedKeyDer = node.der();
                return;
            }
            X509Certificate cert = tryCert(node.der());
            if (cert != null) { certificates.add(cert); return; }
        }
        if (node.isConstructed()) for (Der.Node c : node.children()) collect(c);
    }

    private static boolean isPbe(byte[] oid) {
        StringBuilder s = new StringBuilder();
        for (byte b : oid) s.append(String.format("%02x", b));
        String h = s.toString();
        return h.startsWith("2a864886f70d0105") || h.startsWith("2a864886f70d010c01");
    }

    private static X509Certificate tryCert(byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) { return null; }
    }

    public PrivateKey privateKey(char[] password) throws Exception {
        if (encryptedKeyDer == null) throw new IllegalStateException("record '" + label + "' has no private key");
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(encryptedKeyDer);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(epki.getAlgName());
        SecretKey sk = skf.generateSecret(new PBEKeySpec(password));
        Cipher c = Cipher.getInstance(epki.getAlgName());
        c.init(Cipher.DECRYPT_MODE, sk, epki.getAlgParameters());
        PKCS8EncodedKeySpec spec = epki.getKeySpec(c);
        String alg = certificate() != null ? certificate().getPublicKey().getAlgorithm() : "RSA";
        return KeyFactory.getInstance(alg).generatePrivate(spec);
    }

    /** Appends a whole byte[] to a buffer (ByteArrayOutputStream.write(byte[],int,int) is exception-free). */
    private static void put(ByteArrayOutputStream o, byte[] b) { o.write(b, 0, b.length); }

    private static byte[] sha1(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-1").digest(b); }
    private static byte[] be(int v) {
        return new byte[]{(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }
}
