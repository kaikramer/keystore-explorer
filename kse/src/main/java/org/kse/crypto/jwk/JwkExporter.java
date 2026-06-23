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
package org.kse.crypto.jwk;

import java.security.cert.X509Certificate;

/**
 * Implementers knows how to export an asymmetric key
 */
public interface JwkExporter {

    /**
     * Export a {@link java.security.PublicKey} or {@link java.security.PrivateKey} instance
     *
     * @param alias The key alias. Used for the JWK keyId. If null, the keyId is generated from the
     *            JWK thumbprint.
     * @param chain The certificate chain. Include the certificate chain for when exporting a key pair.
     * @return JWK/JWE encoded private or public key.
     */
    String export(String alias, X509Certificate[] chain);

}
