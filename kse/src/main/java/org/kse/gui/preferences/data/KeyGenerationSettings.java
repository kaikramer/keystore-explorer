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

package org.kse.gui.preferences.data;

import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.secretkey.PasswordType;
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
    private KeyPairType mlDSAParameterSet = KeyPairType.MLDSA44;
    private KeyPairType mlKEMParameterSet = KeyPairType.MLKEM768; // NIST recommended default
    private KeyPairType slhDsaParameterSet = KeyPairType.SLHDSA_SHA2_128F;

    private SecretKeyType secretKeyType = SecretKeyType.AES;
    private int secretKeySize = 128;

    private PasswordType passwordType = PasswordType.PBEWithHmacSHA256AndAES_128;


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

    public PasswordType getPasswordType() {
        return passwordType;
    }

    public void setPasswordType(PasswordType passwordType) {
        this.passwordType = passwordType;
    }

    public KeyPairType getMLDSAParameterSet() {
        return mlDSAParameterSet;
    }

    public void setMLDSAParameterSet(KeyPairType keyPairType) {
        if (KeyPairType.isMlDSA(keyPairType)) {
            mlDSAParameterSet = keyPairType;
        }
    }

    public KeyPairType getMLKEMParameterSet() {
        return mlKEMParameterSet;
    }

    public void setMLKEMParameterSet(KeyPairType keyPairType) {
        if (KeyPairType.isMlKEM(keyPairType)) {
            mlKEMParameterSet = keyPairType;
        }
    }

    public KeyPairType getSlhDsaParameterSet() {
        return slhDsaParameterSet;
    }

    public void setSlhDsaParameterSet(KeyPairType keyPairType) {
        if (KeyPairType.isSlhDsa(keyPairType)) {
            slhDsaParameterSet = keyPairType;
        }
    }
}
