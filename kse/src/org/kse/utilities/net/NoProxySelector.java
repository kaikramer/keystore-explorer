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

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Proxy selector for no proxy, i.e. for a direct connection to the internet.
 */
public class NoProxySelector extends ProxySelector {
    /**
     * Construct NoProxySelector.
     */
    public NoProxySelector() {
    }

    /**
     * Get a list of proxies for the supplied URI.
     *
     * @param uri The URI that a connection is required to
     * @return List of proxies
     */
    @Override
    public List<Proxy> select(URI uri) {
        ArrayList<Proxy> proxies = new ArrayList<>();
        proxies.add(Proxy.NO_PROXY);

        return proxies;
    }

    /**
     * Connection failed. Do nothing.
     *
     * @param uri           The URI that the proxy at socketAddress failed to serve
     * @param socketAddress The socket address of the proxy/SOCKS server
     * @param ioException   The I/O exception thrown when the connect failed
     */
    @Override
    public void connectFailed(URI uri, SocketAddress socketAddress, IOException ioException) {
        /*
         * Do nothing. Documentation of base class ProxySelector suggests that
         * this method may be used to affect what the select method returns.
         * This is not relevant to us
         */
    }

    /**
     * Is this NoProxySelector object equal to another object?
     *
     * @param object Object to compare NoProxySelector with.
     * @return true if the equal, false otherwise.
     */
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }

        if (!(object instanceof NoProxySelector)) {
            return false;
        }

        // Any NoProxySelector is equal to any other NoProxySelector
        return true;
    }
}
