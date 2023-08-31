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
package org.kse.crypto.privatekey;

import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes128_CBC;
import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes256_CBC;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.des_EDE3_CBC;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4;

import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.PBKDF2Config;

/**
 * Enumeration of Password based Encryption (PBE) Types supported by Pkcs8Util.
 */
public enum Pkcs8PbeType implements PbeType {

    // PBE algorithms from PKCS#12
    SHA1_128BIT_RC4(pbeWithSHAAnd128BitRC4, "Pkcs8PbeType.PbeWithSha1And128BitRc4"),
    SHA1_40BIT_RC4(pbeWithSHAAnd40BitRC4, "Pkcs8PbeType.PbeWithSha1And40BitRc4"),
    SHA1_3KEY_DESEDE(pbeWithSHAAnd3_KeyTripleDES_CBC, "Pkcs8PbeType.PbeWithSha1And3KeyDesede"),
    SHA1_2KEY_DESEDE(pbeWithSHAAnd2_KeyTripleDES_CBC, "Pkcs8PbeType.PbeWithSha1And2KeyDesede"),
    SHA1_128BIT_RC2(pbeWithSHAAnd128BitRC2_CBC, "Pkcs8PbeType.PbeWithSha1And128BitRc2"),
    SHA1_40BIT_RC2(pbeWithSHAAnd40BitRC2_CBC, "Pkcs8PbeType.PbeWithSha1And40bitRc2"),

    // PKCS#5 2.0/2.1 PBES2 algorithms
    PBES2_3DES_SHA1(des_EDE3_CBC, PBKDF2Config.PRF_SHA1, "Pkcs8PbeType.Pbes2WithSha1And3Des"),
    PBES2_AES128_SHA1(id_aes128_CBC, PBKDF2Config.PRF_SHA1, "Pkcs8PbeType.Pbes2WithSha1AndAes128"),
    PBES2_AES256_SHA1(id_aes256_CBC, PBKDF2Config.PRF_SHA1, "Pkcs8PbeType.Pbes2WithSha1AndAes256"),
    PBES2_AES256_SHA256(id_aes256_CBC, PBKDF2Config.PRF_SHA256, "Pkcs8PbeType.Pbes2WithSha256AndAes256");

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/privatekey/resources");
    private ASN1ObjectIdentifier oid;
    private String friendlyKey;
    private AlgorithmIdentifier prfOid = null;

    Pkcs8PbeType(ASN1ObjectIdentifier oid, String friendlyKey) {
        this.oid = oid;
        this.friendlyKey = friendlyKey;
    }

    Pkcs8PbeType(ASN1ObjectIdentifier oid, AlgorithmIdentifier prfOid, String friendlyKey) {
        this.oid = oid;
        this.prfOid = prfOid;
        this.friendlyKey = friendlyKey;
    }

    /**
     * PBE type OID.
     *
     * @return OID of PBE algorithm
     */
    public ASN1ObjectIdentifier oid() {
        return oid;
    }

    /**
     * Pseudo random function for PBES2 algorithms
     * @return
     */
    public AlgorithmIdentifier prf() {
        return prfOid;
    }

    /**
     * Get type's friendly name.
     *
     * @return Friendly name resource key name
     */
    @Override
    public String friendly() {
        return res.getString(friendlyKey);
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
