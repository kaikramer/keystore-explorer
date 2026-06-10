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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import javax.security.auth.x500.X500Principal;

import org.kse.crypto.keystore.kdb.asn1.Der;

/**
 * Builds X.509 v3 certificates and PKCS#10 certificate requests using only the JDK — no
 * BouncyCastle. The JDK provides DER for the subject {@link X500Principal} and the
 * {@link PublicKey} (SubjectPublicKeyInfo) and signing via {@link Signature}; this class
 * assembles the surrounding TBSCertificate / CertificationRequest structures.
 */
public final class X509Builder {

    private X509Builder() {}

    /** OIDs for common signature algorithms. */
    private static byte[] sigOid(String javaSigAlg) {
        switch (javaSigAlg) {
            case "SHA256withRSA": return oid("2a864886f70d01010b");
            case "SHA384withRSA": return oid("2a864886f70d01010c");
            case "SHA512withRSA": return oid("2a864886f70d01010d");
            case "SHA1withRSA":   return oid("2a864886f70d010105");
            case "SHA256withECDSA": return oid("2a8648ce3d040302");
            case "SHA384withECDSA": return oid("2a8648ce3d040303");
            default: throw new IllegalArgumentException("unsupported sig alg " + javaSigAlg);
        }
    }

    /** Self-signed certificate. */
    public static X509Certificate selfSigned(String dn, KeyPair kp, int days, String sigAlg)
            throws Exception {
        return build(new X500Principal(dn), kp.getPublic(), new X500Principal(dn),
            kp.getPrivate(), days, sigAlg, true);
    }

    /** Certificate signed by an issuer (CA). */
    public static X509Certificate sign(String subjectDn, PublicKey subjectKey,
            X509Certificate issuer, PrivateKey issuerKey, int days, String sigAlg) throws Exception {
        return build(new X500Principal(subjectDn), subjectKey,
            issuer.getSubjectX500Principal(), issuerKey, days, sigAlg, false);
    }

    private static X509Certificate build(X500Principal subject, PublicKey subjectKey,
            X500Principal issuer, PrivateKey signingKey, int days, String sigAlg, boolean ca)
            throws Exception {
        byte[] algId = Der.sequence(Der.encode(0x06, sigStripOid(sigAlg)), nullParamsIfRsa(sigAlg));
        long now = System.currentTimeMillis();
        byte[] validity = Der.sequence(time(new Date(now - 60_000L)),
                                       time(new Date(now + days * 86_400_000L)));
        byte[] serial = Der.integer(Math.abs(new SecureRandom().nextLong() & 0x7fffffffffffffffL));

        byte[] version = Der.encode(0xA0, Der.integer(2)); // v3
        byte[] extensions = Der.encode(0xA3, Der.sequence(
            basicConstraints(ca),
            subjectKeyId(subjectKey),
            keyUsage(ca)));
        byte[] tbs = Der.sequence(
            version, serial, algId,
            issuer.getEncoded(), validity, subject.getEncoded(),
            subjectKey.getEncoded(), extensions);

        Signature sg = Signature.getInstance(sigAlg);
        sg.initSign(signingKey);
        sg.update(tbs);
        byte[] sig = sg.sign();
        byte[] sigBits = Der.encode(0x03, prepend0(sig));

        byte[] cert = Der.sequence(tbs, algId, sigBits);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(cert));
    }

    /** PKCS#10 certificate request DER. */
    public static byte[] csr(String dn, KeyPair kp, String sigAlg) throws Exception {
        byte[] algId = Der.sequence(Der.encode(0x06, sigStripOid(sigAlg)), nullParamsIfRsa(sigAlg));
        byte[] cri = Der.sequence(
            Der.integer(0),                                  // version
            new X500Principal(dn).getEncoded(),              // subject
            kp.getPublic().getEncoded(),                     // SPKI
            Der.encode(0xA0, new byte[0]));                  // attributes [0] (empty)
        Signature sg = Signature.getInstance(sigAlg);
        sg.initSign(kp.getPrivate());
        sg.update(cri);
        byte[] sig = sg.sign();
        return Der.sequence(cri, algId, Der.encode(0x03, prepend0(sig)));
    }

    /** Builds a v2 X.509 CRL signed by the issuer, revoking the given serials (now). */
    public static byte[] crl(X509Certificate issuer, PrivateKey issuerKey,
                             java.util.List<BigInteger> revoked, int nextDays, String sigAlg)
            throws Exception {
        byte[] algId = Der.sequence(Der.encode(0x06, sigOid(sigAlg)), nullParamsIfRsa(sigAlg));
        long now = System.currentTimeMillis();
        java.io.ByteArrayOutputStream entries = new java.io.ByteArrayOutputStream();
        for (BigInteger s : revoked) {
            byte[] entry = Der.sequence(Der.encode(0x02, s.toByteArray()), time(new Date(now)));
            entries.write(entry, 0, entry.length);
        }
        byte[] revokedSeq = revoked.isEmpty() ? new byte[0] : Der.encode(0x30, entries.toByteArray());
        byte[] tbs = Der.sequence(
            Der.integer(1),                       // version v2
            algId,
            issuer.getSubjectX500Principal().getEncoded(),
            time(new Date(now)),
            time(new Date(now + (long) nextDays * 86_400_000L)),
            revokedSeq);
        Signature sg = Signature.getInstance(sigAlg);
        sg.initSign(issuerKey);
        sg.update(tbs);
        return Der.sequence(tbs, algId, Der.encode(0x03, prepend0(sg.sign())));
    }

    // --------------------------------------------------------------- helpers

    private static byte[] sigStripOid(String sigAlg) { return sigOid(sigAlg); }

    private static byte[] nullParamsIfRsa(String sigAlg) {
        return sigAlg.endsWith("RSA") ? Der.encode(0x05, new byte[0]) : new byte[0];
    }

    private static byte[] time(Date d) {
        // UTCTime for years < 2050, else GeneralizedTime
        TimeZone utc = TimeZone.getTimeZone("UTC");
        @SuppressWarnings("deprecation")
        int year = d.getYear() + 1900;
        if (year < 2050) {
            SimpleDateFormat f = new SimpleDateFormat("yyMMddHHmmss'Z'");
            f.setTimeZone(utc);
            return Der.encode(0x17, f.format(d).getBytes());
        }
        SimpleDateFormat f = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        f.setTimeZone(utc);
        return Der.encode(0x18, f.format(d).getBytes());
    }

    // ext ::= SEQ { OID, critical BOOLEAN OPTIONAL, OCTETSTRING value }
    private static byte[] extension(String oidHex, boolean critical, byte[] value) {
        byte[] crit = critical ? Der.encode(0x01, new byte[]{(byte) 0xFF}) : new byte[0];
        return Der.sequence(Der.encode(0x06, oid(oidHex)), crit, Der.encode(0x04, value));
    }

    private static byte[] basicConstraints(boolean ca) {
        byte[] v = ca ? Der.sequence(Der.encode(0x01, new byte[]{(byte) 0xFF})) // cA=TRUE
                      : Der.sequence();                                          // empty: cA=FALSE
        return extension("551d13", true, v); // 2.5.29.19, critical
    }

    private static byte[] subjectKeyId(PublicKey key) throws Exception {
        // SKI = SHA1 of the subjectPublicKey BIT STRING contents
        Der.Node spki = Der.parse(key.getEncoded());
        Der.Node bit = spki.children().get(1);            // BIT STRING
        byte[] content = bit.content();
        byte[] keyBits = new byte[content.length - 1];    // drop unused-bits byte
        System.arraycopy(content, 1, keyBits, 0, keyBits.length);
        byte[] ski = java.security.MessageDigest.getInstance("SHA-1").digest(keyBits);
        return extension("551d0e", false, Der.encode(0x04, ski)); // 2.5.29.14
    }

    private static byte[] keyUsage(boolean ca) {
        // CA: keyCertSign(5)+cRLSign(6) = bits ...0000011 -> 0x06 ; leaf: digitalSignature(0)+keyEncipherment(2)=0xA0
        byte[] bits = ca ? new byte[]{0x01, 0x06} : new byte[]{0x00, (byte) 0xA0};
        return extension("551d0f", true, Der.encode(0x03, bits)); // 2.5.29.15
    }

    private static byte[] prepend0(byte[] b) {
        byte[] out = new byte[b.length + 1];
        System.arraycopy(b, 0, out, 1, b.length);
        return out; // leading 0 = "0 unused bits"
    }

    private static byte[] oid(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        return out;
    }
}
