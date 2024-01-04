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
package org.kse.crypto.digest;

import java.util.ResourceBundle;

/**
 * Enumeration of hash algorithms supported by the {@link PublicKeyFingerprintAlgorithm} class.
 */
public enum PublicKeyFingerprintAlgorithm {

    // @formatter:off

	SKI_METHOD1("PublicKeyFingerprintAlgorithm.SkiMethod1"),
	SKI_METHOD2("PublicKeyFingerprintAlgorithm.SkiMethod2"),
	SHA1_OVER_SPKI("PublicKeyFingerprintAlgorithm.Sha1overSpki"),
	SHA256_OVER_SPKI("PublicKeyFingerprintAlgorithm.Sha256overSpki");

	// @formatter:on

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/digest/resources");

    private String resBundleKey;

    PublicKeyFingerprintAlgorithm(String resBundleKey) {
        this.resBundleKey = resBundleKey;
    }

    /**
     * Get fingerprint algorithm's friendly name.
     *
     * @return Friendly name
     */
    public String friendly() {
        return res.getString(resBundleKey);
    }

    /**
     * Returns friendly name.
     *
     * @return Friendly name
     */
    @Override
    public String toString() {
        return friendly();
    }
}
