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
package org.kse.crypto.keystore.kdb.asn1;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal DER (ASN.1) reader/writer — just enough to navigate IBM CMS key-database records
 * and to build the few structures the writer needs. No external dependencies.
 */
public final class Der {

    /** A parsed TLV node, with a view onto the backing byte array. */
    public static final class Node {
        public final int tag;          // full first tag byte (class+constructed+number for low tags)
        public final byte[] backing;
        public final int start;        // offset of the tag byte
        public final int headerLen;    // tag + length bytes
        public final int contentLen;   // length of the value
        Node(int tag, byte[] backing, int start, int headerLen, int contentLen) {
            this.tag = tag; this.backing = backing; this.start = start;
            this.headerLen = headerLen; this.contentLen = contentLen;
        }
        public boolean isConstructed() { return (tag & 0x20) != 0; }
        public int contentStart() { return start + headerLen; }
        public int totalLen() { return headerLen + contentLen; }
        /** Full DER encoding of this node (tag+len+value). */
        public byte[] der() {
            byte[] out = new byte[totalLen()];
            System.arraycopy(backing, start, out, 0, out.length);
            return out;
        }
        /** Just the value bytes. */
        public byte[] content() {
            byte[] out = new byte[contentLen];
            System.arraycopy(backing, contentStart(), out, 0, contentLen);
            return out;
        }
        /** Children of a constructed node, in order. */
        public List<Node> children() {
            List<Node> out = new ArrayList<>();
            int o = contentStart();
            int end = o + contentLen;
            while (o < end) {
                Node c = read(backing, o);
                out.add(c);
                o += c.totalLen();
            }
            return out;
        }
    }

    private Der() {}

    /** Reads a single TLV starting at {@code off}. */
    public static Node read(byte[] b, int off) {
        int tag = b[off] & 0xFF;
        int lenByte = b[off + 1] & 0xFF;
        int headerLen;
        int contentLen;
        if (lenByte < 0x80) {
            contentLen = lenByte;
            headerLen = 2;
        } else {
            int n = lenByte & 0x7F;
            int len = 0;
            for (int i = 0; i < n; i++) {
                len = (len << 8) | (b[off + 2 + i] & 0xFF);
            }
            contentLen = len;
            headerLen = 2 + n;
        }
        return new Node(tag, b, off, headerLen, contentLen);
    }

    /** Parses the single top-level TLV of a complete DER blob. */
    public static Node parse(byte[] der) {
        return read(der, 0);
    }

    // --------------------------------------------------------------- encoder

    /** Encodes a tag + value as DER (with definite length). */
    public static byte[] encode(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, value.length);
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    /** Encodes a SEQUENCE from already-encoded member DER blobs. */
    public static byte[] sequence(byte[]... members) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] m : members) body.write(m, 0, m.length);
        return encode(0x30, body.toByteArray());
    }

    public static byte[] integer(long v) {
        // minimal two's-complement encoding for small non-negative values
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        if (v == 0) { bo.write(0); }
        else {
            byte[] tmp = new byte[8];
            int i = 8;
            long x = v;
            while (x != 0) { tmp[--i] = (byte) (x & 0xFF); x >>>= 8; }
            if ((tmp[i] & 0x80) != 0) bo.write(0); // keep positive
            bo.write(tmp, i, 8 - i);
        }
        return encode(0x02, bo.toByteArray());
    }

    private static void writeLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else {
            byte[] tmp = new byte[4];
            int i = 4;
            int x = len;
            while (x != 0) { tmp[--i] = (byte) (x & 0xFF); x >>>= 8; }
            out.write(0x80 | (4 - i));
            out.write(tmp, i, 4 - i);
        }
    }
}
