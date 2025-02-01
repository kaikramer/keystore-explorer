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

package org.kse.utilities.net;

import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;

import javax.swing.JFrame;

import org.kse.gui.error.DError;
import org.kse.gui.preferences.data.ProxySettings;

/**
 * This class translates between the ProxySettings in the KsePreferences and the currently active proxy settings.
 */
public class ProxySettingsUpdater {

    /**
     * Updates system proxy settings
     * @param proxySettings Proxy settings from config
     */
    public static void updateSystem(ProxySettings proxySettings) {

        // default should be system settings because of "java.net.useSystemProxies=true", save it for later usage
        SystemProxySelector.setSystemProxySelector(ProxySelector.getDefault());

        switch (proxySettings.getActiveConfigurationType()) {
        case NONE:
            ProxySelector.setDefault(new NoProxySelector());
            break;
        case PAC:
            // Use PAC URL for proxy configuration
            String pacUrl = proxySettings.getPacUrl();
            if (pacUrl != null) {
                try {
                    ProxySelector.setDefault(new PacProxySelector(new URI(pacUrl)));
                } catch (URISyntaxException e) {
                    DError.displayError(new JFrame(), e);
                    ProxySelector.setDefault(new NoProxySelector());
                }
            } else {
                ProxySelector.setDefault(new NoProxySelector());
            }
            break;
        case MANUAL:
            // Use manual settings for HTTP, HTTPS and SOCKS
            ProxyAddress httpProxyAddress = null;
            ProxyAddress httpsProxyAddress = null;
            ProxyAddress socksProxyAddress = null;

            String httpHost = proxySettings.getHttpHost();
            int httpPort = proxySettings.getHttpPort();

            if (httpHost != null && httpPort > 0) {
                httpProxyAddress = new ProxyAddress(httpHost, httpPort);
            }

            String httpsHost = proxySettings.getHttpsHost();
            int httpsPort = proxySettings.getHttpsPort();

            if (httpsHost != null && httpsPort > 0) {
                httpsProxyAddress = new ProxyAddress(httpsHost, httpsPort);
            }

            String socksHost = proxySettings.getSocksHost();
            int socksPort = proxySettings.getSocksPort();

            if (socksHost != null && socksPort > 0) {
                socksProxyAddress = new ProxyAddress(socksHost, socksPort);
            }

            if (httpProxyAddress != null || httpsProxyAddress != null) {
                ProxySelector.setDefault(
                        new ManualProxySelector(httpProxyAddress, httpsProxyAddress, null, socksProxyAddress));
            } else {
                // no manual settings - use no proxy to connect to the Internet
                ProxySelector.setDefault(new NoProxySelector());
            }
            break;
        case SYSTEM:
        default:
            ProxySelector.setDefault(new SystemProxySelector());
            break;
        }
    }

    /**
     * Updates settings from active system
     * @param proxySettings Proxy settings to be updated
     */
    public static ProxySettings updateSettings(ProxySettings proxySettings) {

        // Get current proxy settings
        ProxySelector proxySelector = ProxySelector.getDefault();

        if (proxySelector instanceof NoProxySelector) {
            proxySettings.setActiveConfigurationType(ProxyConfigurationType.NONE);
        } else if (proxySelector instanceof SystemProxySelector) {
            proxySettings.setActiveConfigurationType(ProxyConfigurationType.SYSTEM);
        } else if (proxySelector instanceof PacProxySelector) {
            PacProxySelector pacProxySelector = (PacProxySelector) proxySelector;

            proxySettings.setPacUrl(pacProxySelector.getPacURI().toString());
            proxySettings.setActiveConfigurationType(ProxyConfigurationType.PAC);
        } else if (proxySelector instanceof ManualProxySelector) {
            ManualProxySelector manualProxySelector = (ManualProxySelector) proxySelector;

            ProxyAddress httpProxyAddress = manualProxySelector.getHttpProxyAddress();
            if (httpProxyAddress != null) {
                proxySettings.setHttpHost(httpProxyAddress.getHost());
                proxySettings.setHttpPort(httpProxyAddress.getPort());
            }

            ProxyAddress httpsProxyAddress = manualProxySelector.getHttpsProxyAddress();
            if (httpsProxyAddress != null) {
                proxySettings.setHttpsHost(httpsProxyAddress.getHost());
                proxySettings.setHttpsPort(httpsProxyAddress.getPort());
            }

            ProxyAddress socksProxyAddress = manualProxySelector.getSocksProxyAddress();
            if (socksProxyAddress != null) {
                proxySettings.setSocksHost(socksProxyAddress.getHost());
                proxySettings.setSocksPort(socksProxyAddress.getPort());
            }

            proxySettings.setActiveConfigurationType(ProxyConfigurationType.MANUAL);
        }

        return proxySettings;
    }
}
