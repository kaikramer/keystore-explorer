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
 * Proxy selector for 'manual' proxies, i.e. where individual proxies are
 * specified for each protocol.
 */
public class ManualProxySelector extends ProxySelector {
    private ProxyAddress httpProxyAddress;
    private ProxyAddress httpsProxyAddress;
    private ProxyAddress ftpProxyAddress;
    private ProxyAddress socksProxyAddress;
    private Proxy httpProxy;
    private Proxy httpsProxy;
    private Proxy ftpProxy;
    private Proxy socksProxy;

    /**
     * Construct ManualProxySelector with proxy settings for each protocol.
     * Where a particular setting is not to be set supply null.
     *
     * @param httpProxyAddress  HTTP proxy address
     * @param httpsProxyAddress HTTPS proxy address
     * @param ftpProxyAddress   FTP proxy address
     * @param socksProxyAddress SOCKS proxy address
     */
    public ManualProxySelector(ProxyAddress httpProxyAddress, ProxyAddress httpsProxyAddress,
                               ProxyAddress ftpProxyAddress, ProxyAddress socksProxyAddress) {
        this.httpProxyAddress = httpProxyAddress;
        this.httpsProxyAddress = httpsProxyAddress;
        this.ftpProxyAddress = ftpProxyAddress;
        this.socksProxyAddress = socksProxyAddress;

        // As creation of Proxy objects is time-comsuming we do this on first
        // call to select
    }

    /**
     * Get a list of proxies for the supplied URI.
     *
     * @param uri The URI that a connection is required to
     * @return List of proxies
     */
    @Override
    public List<Proxy> select(URI uri) {
        createProxies();

        ArrayList<Proxy> proxies = new ArrayList<>();

        if ((uri.getScheme().equals("http")) && (httpProxy != null)) {
            proxies.add(httpProxy);
        } else if ((uri.getScheme().equals("https")) && (httpsProxy != null)) {
            proxies.add(httpsProxy);
        } else if ((uri.getScheme().equals("ftp")) && (ftpProxy != null)) {
            proxies.add(ftpProxy);
        } else if (socksProxy != null) // Use SOCKS if available and no proxy yet identified
        {
            proxies.add(socksProxy);
        }

        if (proxies.isEmpty()) {
            proxies.add(Proxy.NO_PROXY);
        }

        return proxies;
    }

    private void createProxies() {
        // Create proxies if they have not been created already
        if ((httpProxy == null) && (httpsProxy == null) && (ftpProxy == null) && (socksProxy == null)) {
            // Note: Proxy.Type.HTTP is used by Proxy to represent al of http,  https and ftp
            if (httpProxyAddress != null) {
                httpProxy = new Proxy(Proxy.Type.HTTP, httpProxyAddress.getInetSocketAddress());
            }

            if (httpsProxyAddress != null) {
                httpsProxy = new Proxy(Proxy.Type.HTTP, httpsProxyAddress.getInetSocketAddress());
            }

            if (ftpProxyAddress != null) {
                ftpProxy = new Proxy(Proxy.Type.HTTP, ftpProxyAddress.getInetSocketAddress());
            }

            if (socksProxyAddress != null) {
                socksProxy = new Proxy(Proxy.Type.SOCKS, socksProxyAddress.getInetSocketAddress());
            }
        }
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
     * Get HTTP proxy address.
     *
     * @return HTTP proxy address or null if none set
     */
    public ProxyAddress getHttpProxyAddress() {
        return httpProxyAddress;
    }

    /**
     * Get HTTPS proxy address.
     *
     * @return HTTPS proxy address or null if none set
     */
    public ProxyAddress getHttpsProxyAddress() {
        return httpsProxyAddress;
    }

    /**
     * Get FTP proxy address.
     *
     * @return FTP proxy address or null if none set
     */
    public ProxyAddress getFtpProxyAddress() {
        return ftpProxyAddress;
    }

    /**
     * Get SOCKS proxy address.
     *
     * @return SOCKS proxy address or null if none set
     */
    public ProxyAddress getSocksProxyAddress() {
        return socksProxyAddress;
    }

    /**
     * Is this ManualProxySelector object equal to another object?
     *
     * @param object Object to compare ManualProxySelector with.
     * @return true if the equal, false otherwise.
     */
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }

        if (!(object instanceof ManualProxySelector)) {
            return false;
        }

        ManualProxySelector cmpManualProxySelector = (ManualProxySelector) object;

        ProxyAddress proxyHttpAddress = this.getHttpProxyAddress();
        ProxyAddress cmpHttpProxyAddress = cmpManualProxySelector.getHttpProxyAddress();

        boolean httpEquals = (proxyHttpAddress == null ?
                              cmpHttpProxyAddress == null :
                              proxyHttpAddress.equals(cmpHttpProxyAddress));

        if (!httpEquals) {
            return false;
        }

        ProxyAddress proxyHttpsAddress = this.getHttpsProxyAddress();
        ProxyAddress cmpHttpsProxyAddress = cmpManualProxySelector.getHttpsProxyAddress();

        boolean httpsEquals = (proxyHttpsAddress == null ?
                               cmpHttpsProxyAddress == null :
                               proxyHttpsAddress.equals(cmpHttpsProxyAddress));

        if (!httpsEquals) {
            return false;
        }

        ProxyAddress proxyFtpAddress = this.getFtpProxyAddress();
        ProxyAddress cmpFtpProxyAddress = cmpManualProxySelector.getFtpProxyAddress();

        boolean ftpEquals = (proxyFtpAddress == null ?
                             cmpFtpProxyAddress == null :
                             proxyFtpAddress.equals(cmpFtpProxyAddress));

        if (!ftpEquals) {
            return false;
        }

        ProxyAddress proxySocksAddress = this.getSocksProxyAddress();
        ProxyAddress cmpSocksProxyAddress = cmpManualProxySelector.getSocksProxyAddress();

        return (proxySocksAddress == null ?
                cmpSocksProxyAddress == null :
                proxySocksAddress.equals(cmpSocksProxyAddress));

    }
}
