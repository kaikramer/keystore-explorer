package org.kse.crypto.x509;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

/**
 * This class represents a Signed Certificate Timestamp (SCT) as used in
 * Certificate Transparency. It parses and stores SCT data including version,
 * log ID, timestamp, extensions, and a digital signature. The class provides
 * methods to deserialize SCT lists from binary data and includes nested enums
 * for hash and signature algorithms.
 */

public class SignedCertificateTimestamp {
    private short version; // uint8
    private byte[] logId; // 32 bytes
    private long timestamp; // uint64
    private byte[] extensions; // variable length
    private DigitallySigned signature;

    public Version getVersion() {
        return Version.getVersion(version);
    }

    public void setVersion(short version) {
        this.version = version;
    }

    public byte[] getLogId() {
        return logId;
    }

    public void setLogId(byte[] logId) {
        this.logId = logId;
    }

    public Date getTimestamp() {
        return new Date(timestamp);
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getExtensions() {
        return extensions;
    }

    public void setExtensions(byte[] extensions) {
        this.extensions = extensions;
    }

    public DigitallySigned getSignature() {
        return signature;
    }

    public void setSignature(DigitallySigned signature) {
        this.signature = signature;
    }

    private static SignedCertificateTimestamp parseSingleSct(ByteBuffer buffer) {
        SignedCertificateTimestamp sct = new SignedCertificateTimestamp();
        sct.version = buffer.get();
        sct.logId = new byte[32];
        buffer.get(sct.logId);
        sct.timestamp = buffer.getLong();
        int extensionsLength = buffer.getShort() & 0xFFFF; // Read uint16 length
        sct.extensions = new byte[extensionsLength];
        buffer.get(sct.extensions);
        sct.signature = new SignedCertificateTimestamp.DigitallySigned();
        sct.signature.hashAlgorithm = buffer.get();
        sct.signature.signatureAlgorithm = buffer.get();
        int signatureLength = buffer.getShort() & 0xFFFF; // Read uint16 length
        sct.signature.signature = new byte[signatureLength];
        buffer.get(sct.signature.signature);

        return sct;
    }

    public static List<SignedCertificateTimestamp> deserializeSct(byte[] data) {
        ByteBuffer listBuffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        int listLength = listBuffer.getShort() & 0xFFFF;

        ByteBuffer sctDataBuffer = listBuffer.slice();
        sctDataBuffer.limit(listLength);
        sctDataBuffer.order(ByteOrder.BIG_ENDIAN);

        List<SignedCertificateTimestamp> signedCertificateTimestamps = new ArrayList<>();
        while (sctDataBuffer.hasRemaining()) {
            int sctLength = sctDataBuffer.getShort() & 0xFFFF;
            byte[] sctBytes = new byte[sctLength];
            sctDataBuffer.get(sctBytes);

            ByteBuffer singleSctBuffer = ByteBuffer.wrap(sctBytes).order(ByteOrder.BIG_ENDIAN);
            signedCertificateTimestamps.add(parseSingleSct(singleSctBuffer));
        }
        return signedCertificateTimestamps;
    }

    public static class DigitallySigned {
        public short hashAlgorithm; // uint8
        public short signatureAlgorithm; // uint8
        public byte[] signature; // variable length

        public String getHashAlgorithm() {
            return HashAlgorithm.getHashAlgo(hashAlgorithm).toString();
        }

        public String getSignatureAlgorithm() {
            return SignatureAlgorithm.getHashAlgo(signatureAlgorithm).toString();
        }
    }

    public static enum Version {
        V1(0, "v1"),
        UNKNOWN_VERSION(256, "UNKNOWN VERSION");

        private int number;
        private String text;

        Version(int number, String text) {
            this.number = number;
            this.text = text;
        }

        public static Version getVersion(int number) {
            return Stream.of(Version.values())
                    .filter(v -> v.number == number).findFirst().orElse(UNKNOWN_VERSION);
        }

        @Override
        public String toString() {
            return text + " (0x" + Integer.toHexString(number) + ")";
        }

    }

    public static enum HashAlgorithm {
        NONE(0, "None"),
        MD5(1, "MD5"),
        SHA1(2, "SHA"),
        SHA224(3, "SHA-224"),
        SHA256(4, "SHA-256"),
        SHA384(5, "SHA-384"),
        SHA512(6, "SHA-512");

        private int number;
        private String algorithm;

        HashAlgorithm(int number, String algorithm) {
            this.number = number;
            this.algorithm = algorithm;
        }

        public static HashAlgorithm getHashAlgo(int number) {
            return Stream.of(HashAlgorithm.values())
                    .filter(ha -> ha.number == number).findFirst().orElse(NONE);
        }

        @Override
        public String toString() {
            return algorithm;
        }
    }

    public static enum SignatureAlgorithm {
        ANONYMOUS(0, "Anonymous"),
        RSA(1, "RSA"),
        DSA(2, "DSA"),
        ECDSA(3, "ECDSA");

        private int number;
        private String algorithm;

        SignatureAlgorithm(int number, String algorithm) {
            this.number = number;
            this.algorithm = algorithm;
        }

        public static SignatureAlgorithm getHashAlgo(int number) {
            return Stream.of(SignatureAlgorithm.values())
                    .filter(ha -> ha.number == number).findFirst().orElse(ANONYMOUS);
        }

        @Override
        public String toString() {
            return algorithm;
        }
    }
}
