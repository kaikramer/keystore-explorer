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
package org.kse.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.junit.jupiter.api.BeforeAll;
import org.kse.KSE;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.gui.passwordmanager.Password;

/**
 * Abstract base class for all private or public key test cases.
 */
public abstract class KeyTestsBase extends CryptoTestsBase {
    protected static final Password PASSWORD = new Password(new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' });
    protected static RSAPrivateCrtKey rsaPrivateKey;
    protected static RSAPublicKey rsaPublicKey;
    protected static DSAPrivateKey dsaPrivateKey;
    protected static DSAPublicKey dsaPublicKey;
    protected static ECPrivateKey ecPrivateKey;
    protected static ECPublicKey ecPublicKey;
    protected static ECPrivateKey gostPrivateKey;
    protected static ECPublicKey gostPublicKey;
    protected static EdDSAPrivateKey eddsaPrivateKey;
    protected static EdDSAPublicKey eddsaPublicKey;
    protected static MLDSAPublicKey mldsaPublicKey;
    /**
     * MLDSA private keys come with different types of encoding, but for now only the combined form is
     * supported by KSE.
     * <p>
     * {@link org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey#getPrivateKey}
     */
    protected static MLDSAPrivateKey mldsaPrivateKeySeedAndExpanded;
    protected static MLKEMPrivateKey mlkemPrivateKey;
    protected static MLKEMPublicKey mlkemPublicKey;
    protected static SLHDSAPrivateKey slhDsaPrivateKey;
    protected static SLHDSAPublicKey slhDsaPublicKey;


    protected static List<PrivateKey> privateKeys() {
        return Arrays.asList(rsaPrivateKey, dsaPrivateKey, ecPrivateKey, gostPrivateKey, eddsaPrivateKey,
                mldsaPrivateKeySeedAndExpanded, mlkemPrivateKey, slhDsaPrivateKey);
    }

    protected static List<PublicKey> publicKeys() {
        return Arrays.asList(rsaPublicKey, dsaPublicKey, ecPublicKey, gostPublicKey, eddsaPublicKey, mldsaPublicKey,
                mlkemPublicKey, slhDsaPublicKey);
    }

    @BeforeAll
    static void initKeys() throws CryptoException {

        if (rsaPrivateKey == null) {
            KeyPair rsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 1024, KSE.BC);
            rsaPrivateKey = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
            rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        }

        if (dsaPrivateKey == null) {
            KeyPair dsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.DSA, 1024, KSE.BC);
            dsaPrivateKey = (DSAPrivateKey) dsaKeyPair.getPrivate();
            dsaPublicKey = (DSAPublicKey) dsaKeyPair.getPublic();
        }

        if (ecPrivateKey == null) {
            KeyPair ecKeyPair = KeyPairUtil.generateECKeyPair("prime192v1", KSE.BC);
            ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
            ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
        }

        if (gostPrivateKey == null) {
            KeyPair gostKeyPair = KeyPairUtil.generateECKeyPair("Tc26-Gost-3410-12-256-paramSetA", KSE.BC);
            gostPrivateKey = (ECPrivateKey) gostKeyPair.getPrivate();
            gostPublicKey = (ECPublicKey) gostKeyPair.getPublic();
        }

        if (eddsaPrivateKey == null) {
            KeyPair eddsaKeyPair = KeyPairUtil.generateECKeyPair("Ed25519", KSE.BC);
            eddsaPrivateKey = (EdDSAPrivateKey) eddsaKeyPair.getPrivate();
            eddsaPublicKey = (EdDSAPublicKey) eddsaKeyPair.getPublic();
        }

        if (mldsaPublicKey == null) {
            KeyPair mldsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.MLDSA44, KSE.BC);
            mldsaPrivateKeySeedAndExpanded = (MLDSAPrivateKey) mldsaKeyPair.getPrivate();
            mldsaPublicKey = (MLDSAPublicKey) mldsaKeyPair.getPublic();
        }

        if (mlkemPublicKey == null) {
            KeyPair mlKemKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.MLKEM512, KSE.BC);
            mlkemPrivateKey = (MLKEMPrivateKey) mlKemKeyPair.getPrivate();
            mlkemPublicKey = (MLKEMPublicKey) mlKemKeyPair.getPublic();
        }

        if (slhDsaPublicKey == null) {
            KeyPair slhDsaKeyPair = KeyPairUtil.generateKeyPair(KeyPairType.SLHDSA_SHA2_128F, KSE.BC);
            slhDsaPrivateKey = (SLHDSAPrivateKey) slhDsaKeyPair.getPrivate();
            slhDsaPublicKey = (SLHDSAPublicKey) slhDsaKeyPair.getPublic();
        }
    }

}
