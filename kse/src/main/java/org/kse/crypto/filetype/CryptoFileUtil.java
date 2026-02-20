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
package org.kse.crypto.filetype;

import static org.kse.crypto.csr.CsrType.PKCS10;
import static org.kse.crypto.filetype.CryptoFileType.CERT;
import static org.kse.crypto.filetype.CryptoFileType.CRL;
import static org.kse.crypto.filetype.CryptoFileType.ENC_MS_PVK;
import static org.kse.crypto.filetype.CryptoFileType.ENC_OPENSSL_PVK;
import static org.kse.crypto.filetype.CryptoFileType.ENC_PKCS8_PVK;
import static org.kse.crypto.filetype.CryptoFileType.JAR;
import static org.kse.crypto.filetype.CryptoFileType.JSON_WEB_TOKEN;
import static org.kse.crypto.filetype.CryptoFileType.OPENSSL_PUB;
import static org.kse.crypto.filetype.CryptoFileType.PEM_KS;
import static org.kse.crypto.filetype.CryptoFileType.UNENC_MS_PVK;
import static org.kse.crypto.filetype.CryptoFileType.UNENC_OPENSSL_PVK;
import static org.kse.crypto.filetype.CryptoFileType.UNENC_PKCS8_PVK;
import static org.kse.crypto.filetype.CryptoFileType.UNKNOWN;
import static org.kse.crypto.keystore.KeyStoreType.BCFKS;
import static org.kse.crypto.keystore.KeyStoreType.BKS;
import static org.kse.crypto.keystore.KeyStoreType.JCEKS;
import static org.kse.crypto.keystore.KeyStoreType.JKS;
import static org.kse.crypto.keystore.KeyStoreType.PEM;
import static org.kse.crypto.keystore.KeyStoreType.PKCS12;
import static org.kse.crypto.keystore.KeyStoreType.UBER;
import static org.kse.crypto.privatekey.EncryptionType.ENCRYPTED;
import static org.kse.crypto.privatekey.EncryptionType.UNENCRYPTED;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.kse.crypto.csr.CsrType;
import org.kse.crypto.csr.pkcs10.Pkcs10Util;
import org.kse.crypto.csr.spkac.Spkac;
import org.kse.crypto.csr.spkac.SpkacException;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.privatekey.EncryptionType;
import org.kse.crypto.privatekey.MsPvkUtil;
import org.kse.crypto.privatekey.OpenSslPvkUtil;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.crypto.publickey.OpenSslPubUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

import com.nimbusds.jwt.JWTParser;

/**
 * Provides utility methods for the detection of cryptographic file types.
 */
public class CryptoFileUtil {
    private static final int JKS_MAGIC_NUMBER = 0xFEEDFEED;
    private static final int JCEKS_MAGIC_NUMBER = 0xCECECECE;

    private static final int ZIP_MAGIC_NUMBER1 = 0x4C5A4950;
    private static final int ZIP_MAGIC_NUMBER2 = 0x504B0304;
    private static final int ZIP_MAGIC_NUMBER3 = 0x504B0506;
    private static final int ZIP_MAGIC_NUMBER4 = 0x504B0708;

    private CryptoFileUtil() {
    }

    /**
     * Detect the cryptographic file type of the supplied input stream.
     *
     * @param file File with cryptographic data
     * @return Type or null if file not of a recognised type
     * @throws IOException If an I/O problem occurred
     * @throws FileNotFoundException If the file does not exist.
     * @throws NoSuchFileException If the file does not exist.
     */
    public static CryptoFileType detectFileType(File file) throws IOException {
        return detectFileType(Files.readAllBytes(file.toPath()));
    }

    /** Attempts to decode Base64 encoded file and for PEM files, remove excessive indentations from each line
     * @param data Cryptographic data
     * @return a byte array of either decoded data or PEM file without excessive indentations
     */
    public static byte[] decodeIfBase64sanitizeIfPem(byte[] data) {
        if (data == null) {
            return null;
        }
        String input = new String(data, StandardCharsets.US_ASCII).trim();
        // data may be a PEM
        if (PemUtil.isPemFormat(input.getBytes())) {
            // remove whitespaces between lines
            return Arrays.stream(input.split("\\R"))
                    .map(String::trim)
                    .collect(Collectors.joining(System.lineSeparator()))
                    .getBytes();
        } else {
            try {
                // handle base64 encoded binary data
                return Base64.getDecoder().decode(new String(data, StandardCharsets.US_ASCII).trim());
            } catch(IllegalArgumentException e) {
                return data;
            }
        }
    }

    /**
     * Detect the cryptographic file type of the supplied input stream.
     *
     * @param data Cryptographic data
     * @return Type or null if file not of a recognised type
     * @throws IOException If an I/O problem occurred
     */
    public static CryptoFileType detectFileType(byte[] data) throws IOException {

        // first handle base64 encoded binary data
        try {
            data =  decodeIfBase64sanitizeIfPem(data);
        } catch(IllegalArgumentException e) {
            // was not valid b64
        }

        List<PemInfo> pemInfos = null;
        try {
            pemInfos = PemUtil.decodeAll(data);
            if (isPemKeyStore(pemInfos)) {
                return PEM_KS;
            }
        } catch (IOException e) {
            // was not valid PEM
        }

        if (isJarFile(data)) {
            return JAR;
        }

        EncryptionType pkcs8EncType = Pkcs8Util.getEncryptionType(data);

        if (pkcs8EncType != null) {
            if (pkcs8EncType == ENCRYPTED) {
                return ENC_PKCS8_PVK;
            } else if (pkcs8EncType == UNENCRYPTED) {
                return UNENC_PKCS8_PVK;
            }
        }

        EncryptionType msPvkEncType = MsPvkUtil.getEncryptionType(data);

        if (msPvkEncType != null) {
            if (msPvkEncType == ENCRYPTED) {
                return ENC_MS_PVK;
            } else if (msPvkEncType == UNENCRYPTED) {
                return UNENC_MS_PVK;
            }
        }

        EncryptionType openSslPvkEncType = OpenSslPvkUtil.getEncryptionType(data);

        if (openSslPvkEncType != null) {
            if (openSslPvkEncType == ENCRYPTED) {
                return ENC_OPENSSL_PVK;
            } else if (openSslPvkEncType == UNENCRYPTED) {
                return UNENC_OPENSSL_PVK;
            }
        }

        try {
            OpenSslPubUtil.load(data);
            return OPENSSL_PUB;
        } catch (Exception ex) {
            // Ignore - not an OpenSSL public key file
        } catch (OutOfMemoryError ex) {
            // Ignore - not an OpenSSL public key file, some files cause the
            // heap space to fill up with the load call
        }

        try {
            if (X509CertUtil.loadCertificates(data).length > 0) {
                return CERT;
            }
        } catch (Exception ex) {
            // Ignore - not a certificate file
        }

        try {
            X509CertUtil.loadCRL(data);
            return CRL;
        } catch (Exception ex) {
            // Ignore - not a CRL file
        }

        CsrType csrType = detectCsrType(data);

        if (csrType != null) {
            return csrType.getCryptoFileType();
        }

        KeyStoreType keyStoreType = detectKeyStoreType(data, pemInfos);

        if (keyStoreType != null) {
            return keyStoreType.getCryptoFileType();
        }

        if (isJwt(data)) {
            return JSON_WEB_TOKEN;
        }

        // Not a recognised type
        return UNKNOWN;
    }

    private static boolean isJarFile(byte[] data) {
        if (data.length < 4) {
            return false;
        }

        int magic = (data[0] << 24) & 0xff000000 | (data[1] << 16) & 0x00ff0000 | (data[2] << 8) & 0x0000ff00 |
                    (data[3]) & 0x000000ff;

        return magic == ZIP_MAGIC_NUMBER1 || magic == ZIP_MAGIC_NUMBER2 || magic == ZIP_MAGIC_NUMBER3 ||
               magic == ZIP_MAGIC_NUMBER4;
    }

    private static boolean isJwt(byte[] data) {
        try {
            JWTParser.parse(new String(data));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static CsrType detectCsrType(byte[] csrData) throws IOException {
        try {
            Pkcs10Util.loadCsr(csrData);
            return PKCS10;
        } catch (Exception ex) {
            // Ignore - not a PKCS #10 file
        } catch (OutOfMemoryError ex) {
            // Ignore - not a PKCS #10 file, some files cause the heap space to fill up with the load call
        }

        try {
            new Spkac(csrData);
            return CsrType.SPKAC;
        } catch (SpkacException ex) {
            // Ignore - not an SPKAC file
        }

        // Not a recognised type
        return null;
    }

    /**
     * Detect the KeyStore type contained in the supplied file.
     *
     * @param file Keystore file
     * @return KeyStore type or null if none matched
     * @throws IOException If an I/O problem occurred
     */
    public static KeyStoreType detectKeyStoreType(File file) throws IOException {
        return detectKeyStoreType(Files.readAllBytes(file.toPath()));
    }

    /**
     * Detect the KeyStore type contained in the supplied file.
     *
     * @param data Keystore data as byte array
     * @return KeyStore type or null if none matched
     * @throws IOException If an I/O problem occurred
     */
    public static KeyStoreType detectKeyStoreType(byte[] data) throws IOException {
        return detectKeyStoreType(data, null);
    }

    private static KeyStoreType detectKeyStoreType(byte[] data, List<PemInfo> pemInfos) throws IOException {

        try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data))) {

            // If less than 4 bytes are available it isn't a KeyStore
            if (dis.available() < 4) {
                return null;
            }

            // Read first integer (4 bytes)
            int i1 = dis.readInt();

            // Test for JKS - starts with appropriate magic number
            if (i1 == JKS_MAGIC_NUMBER) {
                return JKS;
            }

            // Test for JCEKS - starts with appropriate magic number
            if (i1 == JCEKS_MAGIC_NUMBER) {
                return JCEKS;
            }

            // Test for BKS and UBER

            // Both start with a version number of 1 (UBER) or 2 (BKS)
            if (i1 == 1 || i1 == 2) {
                /*
                 * For BKS and UBER the last 20 bytes of the file are the SHA-1
                 * Hash while the byte before that is a ASN1Null (0) indicating
                 * the end of the store. UBER, however, encrypts the store
                 * content making it highly unlikely that the ASN1Null end byte
                 * will be preserved. Therefore if the 21st byte from the end of
                 * the file is a ASN1Null then the KeyStore is BKS
                 */

                if (data.length < 26) {
                    // Insufficient bytes to be BKS or UBER
                    return null;
                }

                // Skip to 21st from last byte (file length minus 21 and the 4 bytes already read)
                dis.skip(data.length - 25l);

                // Read what may be the null byte
                if (dis.readByte() == 0) {
                    // Found null byte - BKS
                    return BKS;
                } else {
                    // No null byte - UBER
                    return UBER;
                }
            }
        }

        if (pemInfos == null) {
            pemInfos = PemUtil.decodeAll(data);
        }
        if (isPemKeyStore(pemInfos)) {
            return PEM;
        }

        // @formatter:off
        /*
            Test for PKCS #12. ASN.1 should look like this:

            PFX ::= ASN1Sequence {
                version ASN1Integer {v3(3)}(v3,...),
                authSafe ContentInfo,
                macData MacData OPTIONAL
            }
         */
        // @formatter:on

        ASN1Primitive pfx = null;
        try {
            pfx = ASN1Primitive.fromByteArray(data);
        } catch (IOException e) {
            // if it cannot be parsed as ASN1, it is certainly not a pfx key store
            return null;
        }

        // Is a sequence...
        if ((pfx instanceof ASN1Sequence)) {
            // Has two or three components...
            ASN1Sequence sequence = (ASN1Sequence) pfx;

            if ((sequence.size() == 2) || (sequence.size() == 3)) {
                // ...the first of which is a version of 3
                ASN1Encodable firstComponent = sequence.getObjectAt(0);

                if (firstComponent instanceof ASN1Integer) {
                    ASN1Integer version = (ASN1Integer) firstComponent;

                    if (version.getValue().intValue() == 3) {
                        return PKCS12;
                    }
                } else if (firstComponent instanceof DLSequence) {
                    return BCFKS;
                }
            }
        }

        // KeyStore type not recognised
        return null;
    }

    private static boolean isPemKeyStore(List<PemInfo> pemInfos) {
        boolean isPemKeyStore = false;
        final Map<String, Integer> pemTypes = new HashMap<>();

        pemInfos.stream().forEach(pi -> countPemTypes(pemTypes, pi.getType()));

        // Assume a PEM containing a mix of keys and certificates is a PEM KeyStore
        isPemKeyStore = pemTypes.size() > 1
                // Assume a PEM containing multiple certificates is a PEM KeyStore
                || pemTypes.getOrDefault(X509CertUtil.CERT_PEM_TYPE, 0) > 1;

        return isPemKeyStore;
    }

    private static void countPemTypes(Map<String, Integer> counts, String type) {
        counts.compute(type, (k, v) -> v != null ? v + 1 : Integer.valueOf(1));
    }
}
