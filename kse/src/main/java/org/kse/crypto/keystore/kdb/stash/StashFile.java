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
package org.kse.crypto.keystore.kdb.stash;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure-Java implementation of the CMS key-database stash (.sth) format.
 *
 * <p>Interoperable with the standard reference tooling: decode/encode round-trips
 * byte-for-byte, and stash files written elsewhere recover the password that opens
 * their companion {@code .kdb}.
 *
 * <p>Two formats exist:
 * <ul>
 *   <li><b>v1</b> (129 bytes, written with {@code -v1stash}): the buffer
 *       {@code password || 0x00 || random-non-zero-padding} (129 bytes) XORed with 0xF5.</li>
 *   <li><b>v8</b> (193 bytes, the default): {@code A(32) || B(32) || CT(129)} where
 *       {@code B = SHA-256(0x01 || A)}, the key {@code KEY = SHA-256(A || B)}, and the
 *       129-byte v1 buffer is XORed with a keystream derived from KEY via HMAC-SHA-256.</li>
 * </ul>
 *
 * <p>Neither format is machine-specific: a stash file is fully portable and can be decoded
 * offline with no access to the originating host.
 */
public final class StashFile {

    /** Obfuscation constant applied to the password buffer in both formats. */
    private static final int XOR = 0xF5;

    /** Fixed key-stretching constant for the v8 keystream (ASCII, 128 chars). */
    private static final byte[] STR =
        ("13EC6D5C885056915AB35FAD2BDDF39F40D7C57B8B4D28F66B61B75F391446FDA"
       + "96751174DBD9713D02E0B38732E763501DBBB85EC60E437929ED2AA8981B36B")
            .getBytes(StandardCharsets.US_ASCII);

    /** Keystream seed prefix: the first six Fibonacci numbers. */
    private static final byte[] FIB = {1, 1, 2, 3, 5, 8};

    private static final int V1_LEN = 129;
    private static final int V8_LEN = 193;
    /** Maximum password length the format will stash (longer passwords are truncated). */
    public static final int MAX_PASSWORD = 0x80;

    private StashFile() {}

    /** Format of a stash file. */
    public enum Version { V1, V8 }

    // ------------------------------------------------------------------ decode

    /** Reads a {@code .sth} file and returns the stored password. */
    public static String decodeFile(Path stashFile) throws IOException {
        return decode(Files.readAllBytes(stashFile));
    }

    /** Decodes raw stash-file bytes and returns the stored password. */
    public static String decode(byte[] stash) {
        byte[] buffer; // the 129-byte XOR-obfuscated password buffer
        if (stash.length == V1_LEN) {
            buffer = stash.clone();
        } else if (stash.length == V8_LEN) {
            byte[] a = slice(stash, 0, 32);
            byte[] b = slice(stash, 32, 32);
            byte[] ct = slice(stash, 64, V1_LEN);
            byte[] expectedB = sha256(concat(new byte[]{0x01}, a));
            if (!MessageDigest.isEqual(b, expectedB)) {
                throw new IllegalArgumentException(
                    "Not a valid v8 stash file (integrity check failed)");
            }
            byte[] key = sha256(concat(a, b));
            byte[] ks = keystream(key, ct.length);
            buffer = new byte[ct.length];
            for (int i = 0; i < ct.length; i++) {
                buffer[i] = (byte) (ct[i] ^ ks[i]);
            }
        } else {
            throw new IllegalArgumentException(
                "Unrecognised stash file length " + stash.length + " (expected 129 or 193)");
        }
        // De-obfuscate and read the NUL-terminated password.
        int end = 0;
        while (end < buffer.length && ((buffer[end] & 0xFF) ^ XOR) != 0) {
            end++;
        }
        byte[] pw = new byte[end];
        for (int i = 0; i < end; i++) {
            pw[i] = (byte) ((buffer[i] & 0xFF) ^ XOR);
        }
        return new String(pw, StandardCharsets.UTF_8);
    }

    /** Returns the format of the given stash bytes without fully decoding. */
    public static Version versionOf(byte[] stash) {
        if (stash.length == V1_LEN) return Version.V1;
        if (stash.length == V8_LEN) return Version.V8;
        throw new IllegalArgumentException("Unrecognised stash file length " + stash.length);
    }

    // ------------------------------------------------------------------ encode

    /** Encodes a password into a v8 (default) stash file, matching the reference tool. */
    public static byte[] encode(String password) {
        return encode(password, Version.V8);
    }

    /** Encodes a password into the requested stash format. */
    public static byte[] encode(String password, Version version) {
        byte[] pw = password.getBytes(StandardCharsets.UTF_8);
        if (pw.length > MAX_PASSWORD) {
            byte[] truncated = new byte[MAX_PASSWORD];
            System.arraycopy(pw, 0, truncated, 0, MAX_PASSWORD);
            pw = truncated;
        }
        // Build password || 0x00 || random-non-zero-padding, then XOR 0xF5 (the v1 buffer).
        byte[] buffer = new byte[V1_LEN];
        SecureRandom rng = new SecureRandom();
        byte[] rand = new byte[V1_LEN];
        rng.nextBytes(rand);
        int p = 0;
        for (; p < pw.length && p < V1_LEN; p++) {
            buffer[p] = pw[p];
        }
        if (p < V1_LEN) {
            buffer[p++] = 0; // NUL terminator
        }
        for (int i = p; i < V1_LEN; i++) {
            // The format never leaves a zero byte in the padding (it would terminate the password).
            int r = rand[i] & 0xFF;
            buffer[i] = (byte) (r == 0 ? (i + 1) & 0xFF : r);
        }
        for (int i = 0; i < V1_LEN; i++) {
            buffer[i] ^= XOR;
        }
        if (version == Version.V1) {
            return buffer;
        }
        // v8: wrap the obfuscated buffer with the HMAC keystream and integrity header.
        byte[] a = new byte[32];
        rng.nextBytes(a);
        byte[] b = sha256(concat(new byte[]{0x01}, a));
        byte[] key = sha256(concat(a, b));
        byte[] ks = keystream(key, buffer.length);
        byte[] ct = new byte[buffer.length];
        for (int i = 0; i < buffer.length; i++) {
            ct[i] = (byte) (buffer[i] ^ ks[i]);
        }
        byte[] out = new byte[V8_LEN];
        System.arraycopy(a, 0, out, 0, 32);
        System.arraycopy(b, 0, out, 32, 32);
        System.arraycopy(ct, 0, out, 64, ct.length);
        return out;
    }

    // --------------------------------------------------------------- internals

    /** Derives the v8 keystream of {@code n} bytes from the 32-byte database key. */
    private static byte[] keystream(byte[] key, int n) {
        // Conditioning: hash until byte[8]==3, then 64 more rounds.
        byte[] s = key;
        while ((s[8] & 0xFF) != 0x03) {
            s = sha256(s);
        }
        for (int i = 0; i < 64; i++) {
            s = sha256(s);
        }
        byte[] seed = hmacSha256(s, STR);
        byte[] state = hmacSha256(seed, FIB);
        byte[] ks = new byte[((n + 31) / 32) * 32];
        int off = 0;
        while (off < ks.length) {
            byte[] blk = hmacSha256(seed, state);
            System.arraycopy(blk, 0, ks, off, 32);
            off += 32;
            // Feedback: state = keystream-so-far || state.
            state = concat(java.util.Arrays.copyOf(ks, off), state);
        }
        return java.util.Arrays.copyOf(ks, n);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static byte[] slice(byte[] src, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
