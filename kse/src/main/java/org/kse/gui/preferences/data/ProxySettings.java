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

package org.kse.gui.preferences.data;

import org.kse.utilities.net.ProxyConfigurationType;

/**
 * Config bean for storing settings for proxy access
 */
public class ProxySettings {
    private ProxyConfigurationType activeConfigurationType = ProxyConfigurationType.SYSTEM;

    // PAC
    private String pacUrl = "";

    // manual
    private String httpHost = null;
    private int httpPort = 0;
    private String httpsHost = null;
    private int httpsPort = 0;
    private String socksHost = null;
    private int socksPort = 0;

    public String getPacUrl() {
        return pacUrl;
    }

    public void setPacUrl(String pacUrl) {
        this.pacUrl = pacUrl;
    }

    public String getHttpHost() {
        return httpHost;
    }

    public void setHttpHost(String httpHost) {
        this.httpHost = httpHost;
    }

    public int getHttpPort() {
        return httpPort;
    }

    public void setHttpPort(int httpPort) {
        this.httpPort = httpPort;
    }

    public String getHttpsHost() {
        return httpsHost;
    }

    public void setHttpsHost(String httpsHost) {
        this.httpsHost = httpsHost;
    }

    public int getHttpsPort() {
        return httpsPort;
    }

    public void setHttpsPort(int httpsPort) {
        this.httpsPort = httpsPort;
    }

    public String getSocksHost() {
        return socksHost;
    }

    public void setSocksHost(String socksHost) {
        this.socksHost = socksHost;
    }

    public int getSocksPort() {
        return socksPort;
    }

    public void setSocksPort(int socksPort) {
        this.socksPort = socksPort;
    }

    public ProxyConfigurationType getActiveConfigurationType() {
        return activeConfigurationType;
    }

    public void setActiveConfigurationType(ProxyConfigurationType activeConfigurationType) {
        this.activeConfigurationType = activeConfigurationType;
    }
}
