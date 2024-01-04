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

package org.kse.crypto.x509;

import java.util.ResourceBundle;

/**
 * Enumeration of extended key usage types.
 */
public enum ExtendedKeyUsageType {
    /**
     * TLS Web Server Authentication
     */
    SERVER_AUTH("1.3.6.1.5.5.7.3.1", "ServerAuthExtKeyUsage"),

    /**
     * TLS Web Client Authentication
     */
    CLIENT_AUTH("1.3.6.1.5.5.7.3.2", "ClientAuthExtKeyUsage"),

    /**
     * Code Signing
     */
    CODE_SIGNING("1.3.6.1.5.5.7.3.3", "CodeSigningExtKeyUsage"),

    /**
     * Document Signing
     */
    DOCUMENT_SIGNING("1.3.6.1.4.1.311.10.3.12", "DocumentSigningExtKeyUsage"),

    /**
     * Adobe PDF Signing
     */
    ADOBE_PDF_SIGNING("1.2.840.113583.1.1.5", "AdobePDFSigningExtKeyUsage"),

    /**
     * Encrypted File System
     */
    ENCRYPTED_FILE_SYSTEM("1.3.6.1.4.1.311.10.3.4", "EncryptedFileSystemExtKeyUsage"),

    /**
     * Smartcard Logon
     */
    SMARTCARD_LOGON("1.3.6.1.4.1.311.20.2.2", "SmartcardLogonExtKeyUsage"),

    /**
     * Any EXtended Key Usage
     */
    ANY_EXTENDED_KEY_USAGE("2.5.29.37.0", "AnyExtendedKeyUsageExtKeyUsage"),

    /**
     * E-mail Protection
     */
    EMAIL_PROTECTION("1.3.6.1.5.5.7.3.4", "EmailProtectionExtKeyUsage"),

    /**
     * IP Security End System
     */
    IPSEC_END_SYSTEM("1.3.6.1.5.5.7.3.5", "IpsecEndSystemExtKeyUsage"),

    /**
     * IP Security Tunnel termination
     */
    IPSEC_TUNNEL("1.3.6.1.5.5.7.3.6", "IpsecTunnelExtKeyUsage"),

    /**
     * IP Security User
     */
    IPSEC_USER("1.3.6.1.5.5.7.3.7", "IpsecUserExtKeyUsage"),

    /**
     * Time Stamping
     */
    TIME_STAMPING("1.3.6.1.5.5.7.3.8", "TimeStampingExtKeyUsage"),

    /**
     * OCSP Signing
     */
    OCSP_SIGNING("1.3.6.1.5.5.7.3.9", "OcspSigningExtKeyUsage"),

    /**
     * Microsoft Server Gated Crypto (SGC)
     */
    MICROSOFT_SGC("1.3.6.1.4.1.311.10.3.3", "MicrosoftSGCExtKeyUsage"),

    /**
     * Netscape Server Gated Crypto (SGC)
     */
    NETSCAPE_SGC("2.16.840.1.113730.4.1", "NetscapeSGCExtKeyUsage"),

    /**
     * Microsoft Server Gated Crypto (SGC)
     */
    VERISIGN_SGC("2.16.840.1.113733.1.8.1", "VeriSignSGCExtKeyUsage"),

    /**
     * TSL signing specified by ETSI TS 102 231 V3.1.2 for the purpose of signing Trust-service Status Lists.
     */
    TSL_SIGNING("0.4.0.2231.3.0", "TSLSignExtKeyUsage");

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
    private String oid;

    private String friendlyKey;

    ExtendedKeyUsageType(String oid, String friendlyKey) {
        this.oid = oid;
        this.friendlyKey = friendlyKey;
    }

    /**
     * Get type's Object Identifier.
     *
     * @return Object Identifier
     */
    public String oid() {
        return oid;
    }

    /**
     * Get type's friendly name.
     *
     * @return Friendly name
     */
    public String friendly() {
        return res.getString(friendlyKey);
    }

    /**
     * Resolve the supplied object identifier to a matching type.
     *
     * @param oid Object identifier
     * @return Extended Key Usage type or null if none
     */
    public static ExtendedKeyUsageType resolveOid(String oid) {
        for (ExtendedKeyUsageType extType : values()) {
            if (oid.equals(extType.oid())) {
                return extType;
            }
        }

        return null;
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
