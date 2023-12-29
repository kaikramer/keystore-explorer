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

package org.kse.utilities.net;

import java.net.InetAddress;
import java.net.UnknownHostException;

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
}
