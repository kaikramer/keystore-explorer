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

package org.kse.crypto.csr.pkcs12;

import org.kse.gui.preferences.data.Pkcs12EncryptionSetting;

/**
 * Provides utility methods relating to PKCS #12 containers.
 */
public class Pkcs12Util {

    /**
     * Updates encryption algorithms to the given settings.
     *
     * @param pkcs12EncryptionSetting Setting for strength of P12 encryption algorithms
     */
    public static void setEncryptionStrength(Pkcs12EncryptionSetting pkcs12EncryptionSetting) {
        switch (pkcs12EncryptionSetting) {
        case strong:
            System.setProperty("keystore.pkcs12.certProtectionAlgorithm", "PBEWithHmacSHA256AndAES_256");
            System.setProperty("keystore.pkcs12.certPbeIterationCount", "10000");
            System.setProperty("keystore.pkcs12.keyProtectionAlgorithm", "PBEWithHmacSHA256AndAES_256");
            System.setProperty("keystore.pkcs12.keyPbeIterationCount", "10000");
            System.setProperty("keystore.pkcs12.macAlgorithm", "HmacPBESHA256");
            System.setProperty("keystore.pkcs12.macIterationCount", "10000");
            break;
        case legacy:
            System.setProperty("keystore.pkcs12.certProtectionAlgorithm", "PBEWithSHA1AndRC2_40");
            System.setProperty("keystore.pkcs12.keyProtectionAlgorithm", "PBEWithSHA1AndDESede");
            System.setProperty("keystore.pkcs12.macAlgorithm", "HmacPBESHA1");
            System.setProperty("keystore.pkcs12.certPbeIterationCount", "50000");
            System.setProperty("keystore.pkcs12.keyPbeIterationCount", "50000");
            System.setProperty("keystore.pkcs12.macIterationCount", "100000");
            break;
        }
    }
}
