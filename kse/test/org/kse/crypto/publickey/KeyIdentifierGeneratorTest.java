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

package org.kse.crypto.publickey;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyTestsBase;

class KeyIdentifierGeneratorTest extends KeyTestsBase {

    @ParameterizedTest(name = "[{index}] {0}")
    @CsvSource({
        "RSA public key, 30820122300D06092A864886F70D01010105000382010F003082010A0282010100F588DFE7628C1E37F83742907F6C87D0FB658225FDE8CB6BA4FF6DE95A23E299F61CE9920399137C090A8AFA42D65E5624AA7A33841FD1E969BBB974EC574C66689377375553FE39104DB734BB5F2577373B1794EA3CE59DD5BCC3B443EB2EA747EFB0441163D8B44185DD413048931BBFB7F6E0450221E0964217CFD92B6556340726040DA8FD7DCA2EEFEA487C374D3F009F83DFEF75842E79575CFC576E1A96FFFC8C9AA699BE25D97F962C06F7112A028080EB63183C504987E58ACA5F192B59968100A0FB51DBCA770B0BC9964FEF7049C75C6D20FD99B4B4E2CA2E77FD2DDC0BB66B130C8C192B179698B9F08BF6A027BBB6E38D518FBDAEC79BB1899D0203010001, 8A747FAF85CDEE95CD3D9CD0E24614F371351D27",
        "EC public key, 3059301306072A8648CE3D020106082A8648CE3D030107034200041E817A88E6783C6F45DADF276EC0FC25E8E2F82B23CC42F788C85C2737C5A211EFF2EF4030AA3D3009EBE3E5114C3E938A7872DBDE1E0DA8AC0198B856A7B6C0, 79BAEA0FD659FCD37ACC960A2161523B6F5325CD",
        "Ed25519 public key, 3043300506032B6571033A00C6CF09424E05F8AF145CB050EB9DC1E118560215AA3E69591AF6DBE9C831E9974755EAF2B7A102E68C782A0E0A4270A92959F7C6D419D9AF00, 94AB60287D32339E815A20A77304E5943E017A48",
    })
    void generate160BitHashId(String testName, String spkiHex, String keyHashHex) throws PEMException, CryptoException {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(Hex.decode(spkiHex));
        PublicKey publicKey = new JcaPEMKeyConverter().setProvider(KSE.BC)
                                                      .getPublicKey(publicKeyInfo);

        KeyIdentifierGenerator cut = new KeyIdentifierGenerator(publicKey);
        String generated160BitHash = Hex.toHexString(cut.generate160BitHashId()).toUpperCase();
        assertThat(generated160BitHash).isEqualTo(keyHashHex);
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @CsvSource({
        "RSA public key, 30820122300D06092A864886F70D01010105000382010F003082010A0282010100F588DFE7628C1E37F83742907F6C87D0FB658225FDE8CB6BA4FF6DE95A23E299F61CE9920399137C090A8AFA42D65E5624AA7A33841FD1E969BBB974EC574C66689377375553FE39104DB734BB5F2577373B1794EA3CE59DD5BCC3B443EB2EA747EFB0441163D8B44185DD413048931BBFB7F6E0450221E0964217CFD92B6556340726040DA8FD7DCA2EEFEA487C374D3F009F83DFEF75842E79575CFC576E1A96FFFC8C9AA699BE25D97F962C06F7112A028080EB63183C504987E58ACA5F192B59968100A0FB51DBCA770B0BC9964FEF7049C75C6D20FD99B4B4E2CA2E77FD2DDC0BB66B130C8C192B179698B9F08BF6A027BBB6E38D518FBDAEC79BB1899D0203010001, 424614F371351D27",
        "EC public key, 3059301306072A8648CE3D020106082A8648CE3D030107034200041E817A88E6783C6F45DADF276EC0FC25E8E2F82B23CC42F788C85C2737C5A211EFF2EF4030AA3D3009EBE3E5114C3E938A7872DBDE1E0DA8AC0198B856A7B6C0, 4161523B6F5325CD",
        "Ed25519 public key, 3043300506032B6571033A00C6CF09424E05F8AF145CB050EB9DC1E118560215AA3E69591AF6DBE9C831E9974755EAF2B7A102E68C782A0E0A4270A92959F7C6D419D9AF00, 4304E5943E017A48",
    })
    void generate64BitHashId(String testName, String spkiHex, String keyHashHex) throws PEMException, CryptoException {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(Hex.decode(spkiHex));
        PublicKey publicKey = new JcaPEMKeyConverter().setProvider(KSE.BC)
                                                      .getPublicKey(publicKeyInfo);

        KeyIdentifierGenerator cut = new KeyIdentifierGenerator(publicKey);
        String generated160BitHash = Hex.toHexString(cut.generate64BitHashId()).toUpperCase();
        assertThat(generated160BitHash).isEqualTo(keyHashHex);
    }

}