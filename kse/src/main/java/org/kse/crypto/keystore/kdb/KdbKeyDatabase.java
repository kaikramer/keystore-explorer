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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Native reader/writer for the CMS key-database container ({@code .kdb}).
 *
 * <p>"CMS" here is the Certificate Management System component of GSKit, as used by
 * enterprise web and application servers — it is unrelated to the RFC 5652 Cryptographic
 * Message Syntax.
 *
 * <p>Layout, big-endian:
 * <pre>
 *   0x00  4   magic  37 48 vv 02   (vv = format version, 04 or 06)
 *   0x04  4   reserved
 *   0x08  8   "X509KEY\0"
 *   0x10  4   record slot size  (default 0x1388 = 5000)
 *   0x14  4   record count
 *   0x18  24  random salt
 *   0x30  M   HMAC(password, header[0x00:0x30])                   -- password verifier
 *   0x30+M M  HMAC(password, header[0x00:0x30+M] || records)      -- integrity MAC
 *   ----  records: count * slotSize bytes, each slot:
 *     +0x00 4  record type (1 key / 2 key-pair)
 *     +0x04 4  record number (1-based)
 *     +0x08 4  DER length
 *     +0x0c    DER record
 *     +..   4  label length
 *     +..      label
 *     +..   4  flags(0) ; 4 len=20 ; SHA1(SPKI) ; 4 len=20 ; SHA1(cert) ; zero pad to slotSize
 * </pre>
 * The HMAC algorithm (and with it the header size {@code 0x30 + 2*M}) depends on the format
 * version in the third magic byte: version 4 (older GSKit releases) uses HMAC-SHA1 (M=20,
 * header 0x58), version 6 uses HMAC-SHA384 (M=48, header 0x90). The record area is identical
 * in both versions. Certificates and labels are stored in the clear; only private keys are
 * encrypted (PBES2 when written by this class; legacy PKCS#12 PBE schemes in older files are
 * decrypted via the JCA provider mechanism).
 */
public final class KdbKeyDatabase {

    /** The three FileDB containers, distinguished by magic last byte and 8-byte type tag. */
    public enum Kind {
        KDB((byte) 0x02, "X509KEY"),   // key database
        RDB((byte) 0x01, "X509KYP"),   // certificate-request database
        CRL((byte) 0x01, "X509CRL");   // CRL database
        final byte magic4; final String tag;
        Kind(byte m, String t) { this.magic4 = m; this.tag = t; }
    }

    /** Container format versions, distinguished by the third magic byte. */
    public enum Version {
        V4((byte) 0x04, "HmacSHA1"),     // older GSKit releases
        V6((byte) 0x06, "HmacSHA384");   // current
        final byte magic3; final String hmacAlg; final int macLen;
        Version(byte m, String alg) {
            this.magic3 = m; this.hmacAlg = alg;
            this.macLen = macLength(alg);
        }
        int verifierOff() { return 0x30; }
        int integrityOff() { return 0x30 + macLen; }
        int headerSize() { return 0x30 + 2 * macLen; }
        static Version of(byte magic3) {
            for (Version v : values()) if (v.magic3 == magic3) return v;
            return null;
        }
        private static int macLength(String alg) {
            try {
                return Mac.getInstance(alg).getMacLength();
            } catch (Exception e) {
                throw new IllegalStateException(alg + " unavailable", e);
            }
        }
    }

    public static final byte[] MAGIC = {0x37, 0x48, 0x06, 0x02};
    public static final int DEFAULT_SLOT_SIZE = 0x1388; // 5000
    private static final int SALT_OFF = 0x18, SALT_LEN = 24;

    private Kind kind = Kind.KDB;
    private Version version = Version.V6;
    private int slotSize;
    private byte[] salt;
    private final List<KdbRecord> records;

    private KdbKeyDatabase(int slotSize, byte[] salt, List<KdbRecord> records) {
        this.slotSize = slotSize;
        this.salt = salt;
        this.records = records;
    }

    public Kind kind() { return kind; }
    public KdbKeyDatabase kind(Kind k) { this.kind = k; return this; }

    public Version version() { return version; }
    public KdbKeyDatabase version(Version v) { this.version = v; return this; }

    public int slotSize() { return slotSize; }
    public List<KdbRecord> records() { return records; }

    public KdbRecord find(String label) {
        for (KdbRecord r : records) if (r.label().equals(label)) return r;
        return null;
    }

    public boolean remove(String label) {
        return records.removeIf(r -> r.label().equals(label));
    }

    public void add(KdbRecord r) {
        if (find(r.label()) != null) {
            throw new IllegalArgumentException("label already exists: " + r.label());
        }
        records.add(r);
    }

    /** Creates a new, empty key database. */
    public static KdbKeyDatabase create() { return create(Kind.KDB); }

    /** Creates a new, empty database of the given kind. */
    public static KdbKeyDatabase create(Kind kind) {
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt);
        for (int i = 0; i < SALT_LEN - 1; i++) if (salt[i] == 0) salt[i] = 1;
        salt[SALT_LEN - 1] = 0;
        return new KdbKeyDatabase(DEFAULT_SLOT_SIZE, salt, new ArrayList<>()).kind(kind);
    }

    // ------------------------------------------------------------------- read

    public static boolean isKdb(byte[] d) {
        if (d.length < 0x10 || d[0] != 0x37 || d[1] != 0x48) return false;
        Version v = Version.of(d[2]);
        if (v == null || d.length < v.headerSize()) return false;
        String tag = new String(d, 8, 7, StandardCharsets.US_ASCII);
        return tag.equals("X509KEY") || tag.equals("X509KYP") || tag.equals("X509CRL");
    }

    /** True only for key databases ({@code .kdb}, type tag X509KEY), not request/CRL databases. */
    public static boolean isKeyDatabase(byte[] d) {
        return isKdb(d) && kindOf(d) == Kind.KDB;
    }

    private static Kind kindOf(byte[] d) {
        String tag = new String(d, 8, 7, StandardCharsets.US_ASCII);
        for (Kind k : Kind.values()) if (k.tag.equals(tag)) return k;
        return Kind.KDB;
    }

    public static KdbKeyDatabase read(Path file) throws IOException {
        return read(Files.readAllBytes(file));
    }

    public static KdbKeyDatabase read(byte[] d) {
        if (!isKdb(d)) throw new IllegalArgumentException("Not a CMS key database (bad magic/type tag)");
        Version version = Version.of(d[2]);
        int slot = be32(d, 0x10);
        int count = be32(d, 0x14);
        if (slot <= 0 || slot > 1 << 24) throw new IllegalArgumentException("bad slot size " + slot);
        byte[] salt = slice(d, SALT_OFF, SALT_LEN);
        List<KdbRecord> recs = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int base = version.headerSize() + i * slot;
            if (base + 12 > d.length) break;
            int type = be32(d, base);
            int num = be32(d, base + 4);
            int derLen = be32(d, base + 8);
            int derOff = base + 12;
            if (derOff + derLen > d.length || d[derOff] != 0x30) continue;
            byte[] der = slice(d, derOff, derLen);
            int lblOff = derOff + derLen;
            int lblLen = be32(d, lblOff);
            int after = lblOff + 4;
            String label = "";
            if (lblLen >= 0 && after + lblLen <= d.length) {
                label = cstr(d, after, lblLen);
                after += lblLen;
            }
            int trailEnd = Math.min(base + slot, d.length);
            byte[] trailing = after <= trailEnd ? slice(d, after, trailEnd - after) : new byte[0];
            recs.add(new KdbRecord(label, type, num, der, trailing));
        }
        return new KdbKeyDatabase(slot, salt, recs).kind(kindOf(d)).version(version);
    }

    // ----------------------------------------------------------- verify/write

    /** Verifies a password against the stored header MAC (works for any database). */
    public boolean verifyPassword(char[] password, byte[] originalHeader) {
        return verify(originalHeader, password);
    }

    /** Convenience: verify using the on-disk header. */
    public static boolean verify(byte[] kdb, char[] password) {
        Version v = kdb.length > 2 ? Version.of(kdb[2]) : null;
        if (v == null || kdb.length < v.headerSize()) return false;
        byte[] expect = slice(kdb, v.verifierOff(), v.macLen);
        byte[] got = hmac(v, password, slice(kdb, 0, v.verifierOff()));
        return java.security.MessageDigest.isEqual(expect, got);
    }

    /** Serialises the whole database, signed with {@code password}. */
    public byte[] serialize(char[] password) {
        // renumber records 1..n
        for (int i = 0; i < records.size(); i++) records.get(i).setRecordNumber(i + 1);

        // grow the slot size if a record (e.g. a post-quantum key) doesn't fit the default;
        // the slot size is declared in the header, so readers handle any value
        for (KdbRecord r : records) {
            slotSize = Math.max(slotSize, r.slotBytesNeeded());
        }

        byte[] header = new byte[version.headerSize()];
        header[0] = 0x37; header[1] = 0x48; header[2] = version.magic3; header[3] = kind.magic4;
        byte[] tag = (kind.tag + "\0").getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(tag, 0, header, 8, tag.length);
        be32(header, 0x10, slotSize);
        be32(header, 0x14, records.size());
        System.arraycopy(salt, 0, header, SALT_OFF, SALT_LEN);
        // verifier over header[0:verifierOff]
        byte[] verifier = hmac(version, password, slice(header, 0, version.verifierOff()));
        System.arraycopy(verifier, 0, header, version.verifierOff(), version.macLen);

        // record slots
        ByteArrayOutputStream recs = new ByteArrayOutputStream();
        for (KdbRecord r : records) {
            byte[] slot = r.toSlot(slotSize);
            recs.write(slot, 0, slot.length);
        }
        byte[] recBytes = recs.toByteArray();

        // integrity MAC over header[0:integrityOff] + records
        byte[] pre = slice(header, 0, version.integrityOff());
        byte[] both = new byte[pre.length + recBytes.length];
        System.arraycopy(pre, 0, both, 0, pre.length);
        System.arraycopy(recBytes, 0, both, pre.length, recBytes.length);
        byte[] integrity = hmac(version, password, both);
        System.arraycopy(integrity, 0, header, version.integrityOff(), version.macLen);

        byte[] out = new byte[header.length + recBytes.length];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(recBytes, 0, out, header.length, recBytes.length);
        return out;
    }

    public void write(Path file, char[] password) throws IOException {
        Files.write(file, serialize(password));
    }

    // --------------------------------------------------------------- helpers

    static byte[] hmac(Version version, char[] password, byte[] msg) {
        try {
            byte[] key = new String(password).getBytes(StandardCharsets.UTF_8);
            if (key.length == 0) {
                // HMAC zero-pads the key to the block size (RFC 2104), so a single zero byte
                // yields the same MAC as the empty key, which SecretKeySpec cannot represent.
                // An empty password is used e.g. by KeyStoreUtil.copy().
                key = new byte[1];
            }
            Mac mac = Mac.getInstance(version.hmacAlg);
            mac.init(new SecretKeySpec(key, version.hmacAlg));
            return mac.doFinal(msg);
        } catch (Exception e) {
            throw new IllegalStateException(version.hmacAlg + " unavailable", e);
        }
    }

    private static int be32(byte[] d, int o) {
        return ((d[o] & 0xFF) << 24) | ((d[o + 1] & 0xFF) << 16)
             | ((d[o + 2] & 0xFF) << 8) | (d[o + 3] & 0xFF);
    }
    private static void be32(byte[] d, int o, int v) {
        d[o] = (byte) (v >>> 24); d[o + 1] = (byte) (v >>> 16);
        d[o + 2] = (byte) (v >>> 8); d[o + 3] = (byte) v;
    }
    private static byte[] slice(byte[] d, int o, int len) {
        byte[] out = new byte[len];
        System.arraycopy(d, o, out, 0, len);
        return out;
    }
    private static String cstr(byte[] d, int o, int len) {
        int end = o, max = o + len;
        while (end < max && d[end] != 0) end++;
        return new String(d, o, end - o, StandardCharsets.UTF_8);
    }
}
