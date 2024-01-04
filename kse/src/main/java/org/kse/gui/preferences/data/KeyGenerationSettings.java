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

package org.kse.gui.preferences.data;

import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.secretkey.SecretKeyType;

/**
 * Config bean for storing settings for key generation
 */
public class KeyGenerationSettings {

    private KeyPairType keyPairType = KeyPairType.RSA;
    private int keyPairSizeRSA = 2048;
    private int keyPairSizeDSA = 1024;
    private String ecCurveSet = "";
    private String ecCurveName = "";

    private SecretKeyType secretKeyType = SecretKeyType.AES;
    private int secretKeySize = 128;


    public KeyPairType getKeyPairType() {
        return keyPairType;
    }

    public void setKeyPairType(KeyPairType keyPairType) {
        this.keyPairType = keyPairType;
    }

    public int getKeyPairSizeRSA() {
        return keyPairSizeRSA;
    }

    public void setKeyPairSizeRSA(int keyPairSizeRSA) {
        this.keyPairSizeRSA = keyPairSizeRSA;
    }

    public int getKeyPairSizeDSA() {
        return keyPairSizeDSA;
    }

    public void setKeyPairSizeDSA(int keyPairSizeDSA) {
        this.keyPairSizeDSA = keyPairSizeDSA;
    }

    public String getEcCurveSet() {
        return ecCurveSet;
    }

    public void setEcCurveSet(String ecCurveSet) {
        this.ecCurveSet = ecCurveSet;
    }

    public String getEcCurveName() {
        return ecCurveName;
    }

    public void setEcCurveName(String ecCurveName) {
        this.ecCurveName = ecCurveName;
    }

    public SecretKeyType getSecretKeyType() {
        return secretKeyType;
    }

    public void setSecretKeyType(SecretKeyType secretKeyType) {
        this.secretKeyType = secretKeyType;
    }

    public int getSecretKeySize() {
        return secretKeySize;
    }

    public void setSecretKeySize(int secretKeySize) {
        this.secretKeySize = secretKeySize;
    }
}
