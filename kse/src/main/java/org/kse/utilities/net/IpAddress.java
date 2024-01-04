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

package org.kse.utilities.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class for determining the current IP address and host name of this machine.
 */
public class IpAddress {

    private static InetAddress localAddr;

    private IpAddress() {
    }

    /**
     * Return IP address
     *
     * @return (One of possibly several) IP address of this machine
     */
    public static String getIpAddress() {
        try {
            if (localAddr == null) {
                localAddr = InetAddress.getLocalHost();
            }
            return localAddr.getHostAddress();
        } catch (UnknownHostException e) {
            return "";
        }
    }

    /**
     * Return host name
     * @return Host name of this machine
     */
    public static String getHostName() {
        try {
            if (localAddr == null) {
                localAddr = InetAddress.getLocalHost();
            }
            return localAddr.getCanonicalHostName();
        } catch (UnknownHostException e) {
            return "";
        }
    }

    /**
     * Use regular expression to evaluate allowable IPV4 address
     *
     * @param host String to check
     * @return True if valid
     */
    public static boolean isValidIPv4Address(String host) {
        String regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$";
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(host);
        return matcher.find();
    }

    /**
     * Use regular expression to evaluate allowable IPV6 address
     *
     * @param host String to check
     * @return True if valid
     */
    public static boolean isValidIPv6Address(String host) {
        String regex = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                       + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:)"
                       + "{1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4})"
                       + "{1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}"
                       + "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:"
                       + "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(host);
        return matcher.find();
    }

    /**
     * Use regular expression to evaluate allowable IP port ranges
     *
     * @param port String to check
     * @return True if valid
     */
    public static boolean isValidPort(String port) {
        String regex = "^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0][0-9]{1,4})|([0-9]{1,4}))$";
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(port);
        return matcher.find();
    }
}
