/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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
package org.kse.crypto.signing;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.CodeSigner;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Helper class for parsing and extracting meta data from jar files
 */
public class JarParser {

    private File jarFile;

    public JarParser(File jarFile) {
        this.jarFile = jarFile;
    }

    /**
     * Extract all signer certificates from this jar file.
     *
     * @return Unordered array with signer certificates
     * @throws IOException if an I/O error has occurred
     */
    public X509Certificate[] getSignerCerificates() throws IOException {
        try (JarFile jf = new JarFile(jarFile, true)) {

            Set<Certificate> allSignerCerts = new HashSet<>();
            Enumeration<JarEntry> entries = jf.entries();

            while (entries.hasMoreElements()) {

                JarEntry entry = entries.nextElement();

                // reading entry completely is required for calling getCodeSigners()/getCertificates()
                readEntry(jf, entry);

                if (!entry.isDirectory()) {
                    CodeSigner[] codeSigners = entry.getCodeSigners();
                    if (codeSigners != null) {
                        for (CodeSigner cs : entry.getCodeSigners()) {
                            allSignerCerts.addAll(cs.getSignerCertPath().getCertificates());
                        }
                    }

                    Certificate[] certificates = entry.getCertificates();
                    if (certificates != null) {
                        allSignerCerts.addAll(Arrays.asList(certificates));
                    }
                }
            }

            return allSignerCerts.stream().map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
        }
    }

    private static void readEntry(JarFile jf, JarEntry je) throws IOException {
        try (InputStream is = jf.getInputStream(je)) {
            byte[] buffer = new byte[8192];
            while ((is.read(buffer, 0, buffer.length)) != -1) {
            }
        }
    }
}
