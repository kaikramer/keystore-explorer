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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x500.X500Name;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X509CertificateGenerator;
import org.kse.crypto.x509.X509CertificateVersion;

/**
 * Test helper that builds X.509 certificates with KeyStore Explorer's BouncyCastle-based
 * {@link X509CertificateGenerator}.
 */
final class TestCertificates {

    private TestCertificates() {
    }

    /** Self-signed certificate. */
    static X509Certificate selfSigned(String dn, KeyPair kp, int days, String sigAlg) throws Exception {
        Date[] validity = validity(days);
        return generator().generateSelfSigned(new X500Name(dn), validity[0], validity[1], kp.getPublic(),
                kp.getPrivate(), SignatureType.resolveJce(sigAlg), serial());
    }

    /** Certificate signed by an issuer (CA). */
    static X509Certificate sign(String subjectDn, PublicKey subjectKey, X509Certificate issuer,
                                PrivateKey issuerKey, int days, String sigAlg) throws Exception {
        Date[] validity = validity(days);
        return generator().generate(new X500Name(subjectDn),
                X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()), validity[0], validity[1],
                subjectKey, issuerKey, SignatureType.resolveJce(sigAlg), serial(), null, null);
    }

    private static X509CertificateGenerator generator() {
        return new X509CertificateGenerator(X509CertificateVersion.VERSION3);
    }

    private static Date[] validity(int days) {
        Date start = new Date(System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(1));
        Date end = new Date(start.getTime() + TimeUnit.DAYS.toMillis(days));
        return new Date[] { start, end };
    }

    private static BigInteger serial() {
        return new BigInteger(64, new SecureRandom()).abs();
    }
}
