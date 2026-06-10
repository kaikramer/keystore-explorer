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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

/** Round-trip tests for the native CMS key-database engine (no native binary needed). */
class KdbKeyDatabaseTest {

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    @Test
    void emptyDatabaseRoundTripsAndVerifies() {
        KdbKeyDatabase db = KdbKeyDatabase.create();
        byte[] bytes = db.serialize("secret".toCharArray());
        assertTrue(KdbKeyDatabase.isKdb(bytes));
        assertTrue(KdbKeyDatabase.isKeyDatabase(bytes));
        assertTrue(KdbKeyDatabase.verify(bytes, "secret".toCharArray()));
        assertFalse(KdbKeyDatabase.verify(bytes, "wrong".toCharArray()));
        assertEquals(0, KdbKeyDatabase.read(bytes).records().size());
    }

    @Test
    void caCertificateRoundTrips() throws Exception {
        KeyPair kp = rsa();
        X509Certificate cert = TestCertificates.selfSigned("CN=Root,O=T", kp, 365, "SHA256withRSA");
        KdbKeyDatabase db = KdbKeyDatabase.create();
        db.add(KdbRecord.caRecord("root", cert));
        byte[] bytes = db.serialize("pw".toCharArray());

        KdbKeyDatabase back = KdbKeyDatabase.read(bytes);
        assertEquals(1, back.records().size());
        KdbRecord r = back.find("root");
        assertNotNull(r);
        assertFalse(r.hasPrivateKey());
        assertEquals(cert.getSubjectX500Principal(), r.certificate().getSubjectX500Principal());
    }

    @Test
    void personalCertificateAndKeyRoundTrip() throws Exception {
        KeyPair kp = rsa();
        X509Certificate cert = TestCertificates.selfSigned("CN=me", kp, 365, "SHA256withRSA");
        byte[] enc = KdbRecord.encryptPrivateKey(kp.getPrivate(), "pw".toCharArray());
        KdbKeyDatabase db = KdbKeyDatabase.create();
        db.add(KdbRecord.personalRecord("me", cert, enc));
        byte[] bytes = db.serialize("pw".toCharArray());

        KdbRecord r = KdbKeyDatabase.read(bytes).find("me");
        assertTrue(r.hasPrivateKey());
        PrivateKey recovered = r.privateKey("pw".toCharArray());
        assertEquals(kp.getPrivate(), recovered);
    }

    @Test
    void emptyPasswordRoundTripsAndVerifies() {
        // KeyStoreUtil.copy() serializes and reloads keystores with an empty password
        KdbKeyDatabase db = KdbKeyDatabase.create();
        byte[] bytes = db.serialize(new char[0]);
        assertTrue(KdbKeyDatabase.verify(bytes, new char[0]));
        assertFalse(KdbKeyDatabase.verify(bytes, "secret".toCharArray()));
        assertEquals(0, KdbKeyDatabase.read(bytes).records().size());
    }

    @Test
    void version4DatabaseRoundTripsAndVerifies() throws Exception {
        KeyPair kp = rsa();
        X509Certificate cert = TestCertificates.selfSigned("CN=Root,O=T", kp, 365, "SHA256withRSA");
        KdbKeyDatabase db = KdbKeyDatabase.create().version(KdbKeyDatabase.Version.V4);
        db.add(KdbRecord.caRecord("root", cert));
        byte[] bytes = db.serialize("secret".toCharArray());

        // v4 header: magic 37 48 04, salt(24) + 2 * HMAC-SHA1(20) = 0x58 bytes before the records
        assertEquals(0x04, bytes[2]);
        assertEquals(0x58 + db.slotSize(), bytes.length);
        assertTrue(KdbKeyDatabase.isKdb(bytes));
        assertTrue(KdbKeyDatabase.isKeyDatabase(bytes));
        assertTrue(KdbKeyDatabase.verify(bytes, "secret".toCharArray()));
        assertFalse(KdbKeyDatabase.verify(bytes, "wrong".toCharArray()));

        KdbKeyDatabase back = KdbKeyDatabase.read(bytes);
        assertEquals(KdbKeyDatabase.Version.V4, back.version());
        assertEquals(cert.getSubjectX500Principal(),
            back.find("root").certificate().getSubjectX500Principal());

        // version survives a read-modify-write cycle
        assertEquals(0x04, back.serialize("secret".toCharArray())[2]);
    }

    @Test
    void changingPasswordReEncryptsKeys() throws Exception {
        KeyPair kp = rsa();
        X509Certificate cert = TestCertificates.selfSigned("CN=me", kp, 365, "SHA256withRSA");
        KdbKeyDatabase db = KdbKeyDatabase.create();
        db.add(KdbRecord.personalRecord("me", cert, KdbRecord.encryptPrivateKey(kp.getPrivate(), "old".toCharArray())));
        byte[] v1 = db.serialize("old".toCharArray());

        // simulate changepw: re-encrypt under new password, re-sign header
        KdbKeyDatabase reread = KdbKeyDatabase.read(v1);
        KdbRecord r = reread.find("me");
        byte[] newEnc = KdbRecord.encryptPrivateKey(r.privateKey("old".toCharArray()), "new".toCharArray());
        reread.remove("me");
        reread.add(KdbRecord.personalRecord("me", r.certificate(), newEnc));
        byte[] v2 = reread.serialize("new".toCharArray());

        assertTrue(KdbKeyDatabase.verify(v2, "new".toCharArray()));
        assertFalse(KdbKeyDatabase.verify(v2, "old".toCharArray()));
        assertEquals(kp.getPrivate(),
            KdbKeyDatabase.read(v2).find("me").privateKey("new".toCharArray()));
    }
}
