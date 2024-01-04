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
package org.kse.utilities.ssl;

import java.security.cert.X509Certificate;

/**
 * Data transfer class for SSL infos.
 */
public class SslConnectionInfos {

    String peerHost;
    int peerPort;
    String protocol;
    String cipherSuite;
    boolean sniEnabled;
    X509Certificate[] serverCertificates;
    X509Certificate[] clientCertificates;

    public String getPeerHost() {
        return peerHost;
    }

    public void setPeerHost(String peerHost) {
        this.peerHost = peerHost;
    }

    public int getPeerPort() {
        return peerPort;
    }

    public void setPeerPort(int peerPort) {
        this.peerPort = peerPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getCipherSuite() {
        return cipherSuite;
    }

    public void setCipherSuite(String cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    public boolean isSniEnabled() {
        return sniEnabled;
    }

    public void setSniEnabled(boolean sniEnabled) {
        this.sniEnabled = sniEnabled;
    }

    public X509Certificate[] getServerCertificates() {
        return serverCertificates;
    }

    public void setServerCertificates(X509Certificate[] serverCertificates) {
        this.serverCertificates = serverCertificates;
    }

    public X509Certificate[] getClientCertificates() {
        return clientCertificates;
    }

    public void setClientCertificates(X509Certificate[] clientCertificates) {
        this.clientCertificates = clientCertificates;
    }
}
