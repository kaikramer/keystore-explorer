/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
package org.kse.utilities.buffer;

import java.security.cert.Certificate;

/**
 * Trusted certificate buffer entry.
 */
public class TrustedCertificateBufferEntry extends BufferEntry {
    private Certificate trustedCertificate;

    /**
     * Construct.
     *
     * @param name               Entry name
     * @param cut                Is entry to be cut?
     * @param trustedCertificate Trusted certificate
     */
    public TrustedCertificateBufferEntry(String name, boolean cut, Certificate trustedCertificate) {
        super(name, cut);

        this.trustedCertificate = trustedCertificate;
    }

    /**
     * Get trusted certificate.
     *
     * @return Trusted certificate
     */
    public Certificate getTrustedCertificate() {
        return trustedCertificate;
    }

    @Override
    void clear() {
    }
}
