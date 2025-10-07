/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.kse.utilities.io.HexUtil;
import org.kse.utilities.oid.ObjectIdUtil;

/**
 * General Name utility methods.
 */
public class GeneralNameUtil {

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");

    // other name
    public static final String UPN_OID = "1.3.6.1.4.1.311.20.2.3";

    private GeneralNameUtil() {
    }

    // @formatter:off

    /*
     * GeneralName ::= CHOICE
     * {
     *      otherName [0] AnotherName,
     *      rfc822Name [1] DERIA5String,
     *      dNSName [2] DERIA5String,
     *      x400Address [3] ORAddress,
     *      directoryName [4] Name,
     *      ediPartyName [5] EDIPartyName,
     *      uniformResourceIdentifier [6] DERIA5String,
     *      iPAddress [7] OCTET STRING,
     *      registeredID [8] OBJECT IDENTIFIER
     * }
     *
     * AnotherName ::= ASN1Sequence
     * {
     *      type-id OBJECT IDENTIFIER,
     *      value [0] EXPLICIT ANY DEFINED BY type-id
     * }
     *
     * EDIPartyName ::= ASN1Sequence
     * {
     *      nameAssigner [0] DirectoryString OPTIONAL,
     *      partyName [1] DirectoryString
     * }
     *
     * DirectoryString ::= CHOICE
     * {
     *      teletexString TeletexString (SIZE (1..MAX),
     *      printableString PrintableString (SIZE (1..MAX)),
     *      universalString UniversalString (SIZE (1..MAX)),
     *      utf8String UTF8String (SIZE (1.. MAX)),
     *      bmpString BMPString (SIZE(1..MAX))
     * }
     */

    // @formatter:on

    /**
     * Extract GeneralName from X500Principal object
     *
     * @param x500Principal X500Principal object
     * @return GeneralName object
     */
    public static GeneralName fromX500Principal(X500Principal x500Principal) {
        X500Name x500Name = X500NameUtils.x500PrincipalToX500Name(x500Principal);
        return new GeneralName(x500Name);
    }

    /**
     * Get string representation for General names that cannot cause a
     * IOException to be thrown. Unsupported are ediPartyName, otherName and
     * x400Address. Returns a blank string for these.
     *
     * @param generalName   General name
     * @param addLinkForURI If true, convert URI to a clickable link
     * @return String representation of general name
     */
    public static String safeToString(GeneralName generalName, boolean addLinkForURI) {

        if (generalName == null) {
            return "";
        }

        switch (generalName.getTagNo()) {
        case GeneralName.directoryName:
            X500Name directoryName = (X500Name) generalName.getName();

            return MessageFormat.format(res.getString("GeneralNameUtil.DirectoryGeneralName"),
                                        directoryName.toString());
        case GeneralName.dNSName:
            DERIA5String dnsName = (DERIA5String) generalName.getName();

            return MessageFormat.format(res.getString("GeneralNameUtil.DnsGeneralName"), dnsName.getString());
        case GeneralName.iPAddress:
            String ipAddressString = parseIpAddress(generalName);
            return MessageFormat.format(res.getString("GeneralNameUtil.IpAddressGeneralName"), ipAddressString);
        case GeneralName.registeredID:
            ASN1ObjectIdentifier registeredId = (ASN1ObjectIdentifier) generalName.getName();

            return MessageFormat.format(res.getString("GeneralNameUtil.RegisteredIdGeneralName"),
                                        ObjectIdUtil.toString(registeredId));
        case GeneralName.rfc822Name:
            DERIA5String rfc822Name = (DERIA5String) generalName.getName();

            return MessageFormat.format(res.getString("GeneralNameUtil.Rfc822GeneralName"), rfc822Name.getString());
        case GeneralName.uniformResourceIdentifier:
            DERIA5String uri = (DERIA5String) generalName.getName();

            String link = addLinkForURI ?
                          "<a href=\"" + uri.getString() + "\">" + uri.getString() + "</a>" :
                          uri.getString();

            return MessageFormat.format(res.getString("GeneralNameUtil.UriGeneralName"), link);
        case GeneralName.otherName:
            // we currently only support UPN in otherName
            return parseUPN(generalName);
        default:
            return "";
        }
    }

    public static boolean isGeneralNameEmpty(GeneralName generalName) {

        if (generalName == null) {
            return true;
        }

        switch (generalName.getTagNo()) {
        case GeneralName.directoryName:
            X500Name directoryName = (X500Name) generalName.getName();
            return (directoryName == null) || (directoryName.getRDNs().length == 0);
        case GeneralName.dNSName:
            DERIA5String dnsName = (DERIA5String) generalName.getName();
            return (dnsName == null) || dnsName.getString().isEmpty();
        case GeneralName.iPAddress:
            byte[] ipAddressBytes = ((ASN1OctetString) generalName.getName()).getOctets();
            return (ipAddressBytes == null) || (ipAddressBytes.length == 0);
        case GeneralName.registeredID:
            ASN1ObjectIdentifier registeredId = (ASN1ObjectIdentifier) generalName.getName();
            return (registeredId == null) || registeredId.toString().isEmpty();
        case GeneralName.rfc822Name:
            DERIA5String rfc822Name = (DERIA5String) generalName.getName();
            return (rfc822Name == null) || rfc822Name.getString().isEmpty();
        case GeneralName.uniformResourceIdentifier:
            DERIA5String uri = (DERIA5String) generalName.getName();
            return (uri == null) || uri.getString().isEmpty();
        case GeneralName.otherName:
            return false;
        default:
            return false;
        }
    }

    public static String parseIpAddress(GeneralName generalName) {
        byte[] ipAddressBytes = ((ASN1OctetString) generalName.getName()).getOctets();
        String ipAddressString = "";

        if (ipAddressBytes.length == 4 || ipAddressBytes.length == 16) {
            try {
                ipAddressString = InetAddress.getByAddress(ipAddressBytes).getHostAddress();
            } catch (UnknownHostException e) {
                //length of IP address has been checked before
            }
        } else {
            if (ipAddressBytes.length == 8 || ipAddressBytes.length == 32) {
                final int newSize = ipAddressBytes.length / 2;
                byte[] ipAddress = new byte[newSize];
                System.arraycopy(ipAddressBytes, 0, ipAddress, 0, newSize);

                try {
                    ipAddressString = InetAddress.getByAddress(ipAddress).getHostAddress();
                } catch (UnknownHostException e) {
                    //length of IP address has been checked before
                }
                byte[] netMask = new byte[newSize];
                System.arraycopy(ipAddressBytes, newSize, netMask, 0, newSize);

                try {
                    String netmaskString = InetAddress.getByAddress(netMask).getHostAddress();
                    ipAddressString += "/" + netmaskString;
                } catch (UnknownHostException e) {
                    //length of IP address has been checked before
                }
            }
        }
        return ipAddressString;
    }

    /**
     * Parse UPN/otherName
     *
     * @param generalName otherName object
     * @return UPN as string
     */
    public static String parseUPN(GeneralName generalName) {
        // OtherName ::= SEQUENCE {
        //    type-id OBJECT IDENTIFIER,
        //    value [0] EXPLICIT ANY DEFINED BY type-id }

        ASN1Sequence otherName = (ASN1Sequence) generalName.getName();
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) otherName.getObjectAt(0);

        if (UPN_OID.equals(oid.getId())) {
            ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) otherName.getObjectAt(1);
            ASN1UTF8String upn = ASN1UTF8String.getInstance(asn1TaggedObject.getBaseObject());
            return MessageFormat.format(res.getString("GeneralNameUtil.OtherGeneralName"), "UPN", upn.getString());
        }

        // fallback to generic handling
        ASN1Encodable value = otherName.getObjectAt(1);
        try {
            return MessageFormat.format(res.getString("GeneralNameUtil.OtherGeneralName"), ObjectIdUtil.toString(oid),
                                        HexUtil.getHexString(value.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
        } catch (IOException e) {
            return MessageFormat.format(res.getString("GeneralNameUtil.OtherGeneralName"), ObjectIdUtil.toString(oid),
                                        "");
        }
    }

    /**
     * Get string representation for all General Names.
     *
     * @param generalName General name
     * @return String representation of general name
     * @throws IOException If general name is invalid
     */
    public static String toString(GeneralName generalName) throws IOException {

        if (generalName == null) {
            return "";
        }

        switch (generalName.getTagNo()) {
        case GeneralName.ediPartyName:

            /* EDIPartyName ::= SEQUENCE {
             *      nameAssigner            [0]     DirectoryString OPTIONAL,
             *      partyName               [1]     DirectoryString }
             */
            ASN1Sequence ediPartyName = (ASN1Sequence) generalName.getName();

            DirectoryString nameAssigner = DirectoryString.getInstance(ediPartyName.getObjectAt(0));
            DirectoryString partyName = DirectoryString.getInstance(ediPartyName.getObjectAt(1));

            String nameAssignerStr = null;
            if (nameAssigner != null) { // Optional
                nameAssignerStr = nameAssigner.getString();
            }

            String partyNameStr = partyName.getString();
            if (nameAssignerStr != null) {
                return MessageFormat.format(res.getString("GeneralNameUtil.EdiPartyGeneralName"), nameAssignerStr,
                                            partyNameStr);
            } else {
                return MessageFormat.format(res.getString("GeneralNameUtil.EdiPartyGeneralNameNoAssigner"),
                                            partyNameStr);
            }
        case GeneralName.otherName:
            return parseUPN(generalName);
        case GeneralName.x400Address:
            /*
             * No support for this at the moment - just get a hex dump
             * The Oracle CertificateFactory blows up if a certificate extension contains this anyway
             */
            ASN1Encodable x400Address = generalName.getName();

            return MessageFormat.format(res.getString("GeneralNameUtil.X400AddressGeneralName"), HexUtil.getHexString(
                    x400Address.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
        default:
            return safeToString(generalName, true);
        }
    }
}
