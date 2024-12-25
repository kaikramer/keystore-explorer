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
package org.kse.gui.preferences;

import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ResourceBundle;

import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;

import org.kse.gui.PlatformUtil;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.utilities.net.IpAddress;
import org.kse.utilities.net.ManualProxySelector;
import org.kse.utilities.net.NoProxySelector;
import org.kse.utilities.net.PacProxySelector;
import org.kse.utilities.net.ProxyAddress;
import org.kse.utilities.net.SystemProxySelector;

import net.miginfocom.swing.MigLayout;

class PanelProxy {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");

    private final DPreferences parent;
    private final KsePreferences preferences;

    private JRadioButton jrbNoProxy;
    private JRadioButton jrbSystemProxySettings;
    private JRadioButton jrbManualProxyConfig;
    private JTextField jtfHttpHost;
    private JTextField jtfHttpPort;
    private JTextField jtfHttpsHost;
    private JTextField jtfHttpsPort;
    private JTextField jtfSocksHost;
    private JTextField jtfSocksPort;
    private JRadioButton jrbAutomaticProxyConfig;
    private JTextField jtfPacUrl;

    PanelProxy(DPreferences parent, KsePreferences preferences) {
        this.parent = parent;
        this.preferences = preferences;
    }

    JPanel initInternetProxyCard() {
        jrbNoProxy = new JRadioButton(res.getString("DPreferences.jrbNoProxy.text"));
        jrbNoProxy.setToolTipText(res.getString("DPreferences.jrbNoProxy.tooltip"));
        PlatformUtil.setMnemonic(jrbNoProxy, res.getString("DPreferences.jrbNoProxy.mnemonic").charAt(0));

        jrbSystemProxySettings = new JRadioButton(res.getString("DPreferences.jrbSystemProxySettings.text"), true);
        jrbSystemProxySettings.setToolTipText(res.getString("DPreferences.jrbSystemProxySettings.tooltip"));
        PlatformUtil.setMnemonic(jrbSystemProxySettings,
                                 res.getString("DPreferences.jrbSystemProxySettings.mnemonic").charAt(0));

        jrbManualProxyConfig = new JRadioButton(res.getString("DPreferences.jrbManualProxyConfig.text"));
        jrbManualProxyConfig.setToolTipText(res.getString("DPreferences.jrbManualProxyConfig.tooltip"));
        PlatformUtil.setMnemonic(jrbManualProxyConfig,
                                 res.getString("DPreferences.jrbManualProxyConfig.mnemonic").charAt(0));

        JLabel jlHttpHost = new JLabel(res.getString("DPreferences.jlHttpHost.text"));

        jtfHttpHost = new JTextField(20);
        jtfHttpHost.setToolTipText(res.getString("DPreferences.jtfHttpHost.tooltip"));
        jtfHttpHost.setEnabled(false);
        jtfHttpHost.setText(preferences.getProxySettings().getHttpHost());
        jtfHttpHost.setCaretPosition(0);

        JLabel jlHttpPort = new JLabel(res.getString("DPreferences.jlHttpPort.text"));

        jtfHttpPort = new JTextField(5);
        jtfHttpPort.setToolTipText(res.getString("DPreferences.jtfHttpPort.tooltip"));
        jtfHttpPort.setEnabled(false);
        jtfHttpPort.setText("" + preferences.getProxySettings().getHttpPort());
        jtfHttpPort.setCaretPosition(0);

        JLabel jlHttpsHost = new JLabel(res.getString("DPreferences.jlHttpsHost.text"));

        jtfHttpsHost = new JTextField(20);
        jtfHttpsHost.setToolTipText(res.getString("DPreferences.jtfHttpsHost.tooltip"));
        jtfHttpsHost.setEnabled(false);
        jtfHttpsHost.setText(preferences.getProxySettings().getHttpsHost());
        jtfHttpsHost.setCaretPosition(0);

        JLabel jlHttpsPort = new JLabel(res.getString("DPreferences.jlHttpsPort.text"));

        jtfHttpsPort = new JTextField(5);
        jtfHttpsPort.setToolTipText(res.getString("DPreferences.jtfHttpsPort.tooltip"));
        jtfHttpsPort.setEnabled(false);
        jtfHttpsPort.setText("" + preferences.getProxySettings().getHttpsPort());
        jtfHttpsPort.setCaretPosition(0);

        JLabel jlSocksHost = new JLabel(res.getString("DPreferences.jlSocksHost.text"));

        jtfSocksHost = new JTextField(20);
        jtfSocksHost.setToolTipText(res.getString("DPreferences.jtfSocksHost.tooltip"));
        jtfSocksHost.setEnabled(false);
        jtfSocksHost.setText(preferences.getProxySettings().getSocksHost());
        jtfSocksHost.setCaretPosition(0);

        JLabel jlSocksPort = new JLabel(res.getString("DPreferences.jlSocksPort.text"));

        jtfSocksPort = new JTextField(5);
        jtfSocksPort.setToolTipText(res.getString("DPreferences.jtfSocksPort.tooltip"));
        jtfSocksPort.setEnabled(false);
        jtfSocksPort.setText("" + preferences.getProxySettings().getSocksPort());
        jtfSocksPort.setCaretPosition(0);

        jrbAutomaticProxyConfig = new JRadioButton(res.getString("DPreferences.jrbAutomaticProxyConfig.text"));
        jrbAutomaticProxyConfig.setToolTipText(res.getString("DPreferences.jrbAutomaticProxyConfig.tooltip"));
        PlatformUtil.setMnemonic(jrbAutomaticProxyConfig,
                                 res.getString("DPreferences.jrbAutomaticProxyConfig.mnemonic").charAt(0));

        JLabel jlPacUrl = new JLabel(res.getString("DPreferences.jlPacUrl.text"));

        jtfPacUrl = new JTextField(30);
        jtfPacUrl.setToolTipText(res.getString("DPreferences.jtfPacUrl.tooltip"));
        jtfPacUrl.setEnabled(false);
        jtfPacUrl.setText(preferences.getProxySettings().getPacUrl());

        ButtonGroup bgProxies = new ButtonGroup();
        bgProxies.add(jrbNoProxy);
        bgProxies.add(jrbSystemProxySettings);
        bgProxies.add(jrbManualProxyConfig);
        bgProxies.add(jrbAutomaticProxyConfig);

        // layout
        JPanel jpInternetProxy = new JPanel();
        jpInternetProxy.setLayout(new MigLayout("insets dialog", "20lp[][]", "20lp[][]"));
        jpInternetProxy.add(jrbNoProxy, "left, span, wrap");
        jpInternetProxy.add(jrbSystemProxySettings, "left, span, wrap");
        jpInternetProxy.add(jrbManualProxyConfig, "left, span, wrap");
        jpInternetProxy.add(jlHttpHost, "gap unrel, skip, right");
        jpInternetProxy.add(jtfHttpHost, "");
        jpInternetProxy.add(jlHttpPort, "gap unrel, right");
        jpInternetProxy.add(jtfHttpPort, "wrap");
        jpInternetProxy.add(jlHttpsHost, "gap unrel, skip, right");
        jpInternetProxy.add(jtfHttpsHost, "");
        jpInternetProxy.add(jlHttpsPort, "gap unrel, right");
        jpInternetProxy.add(jtfHttpsPort, "wrap");
        jpInternetProxy.add(jlSocksHost, "gap unrel, skip, right");
        jpInternetProxy.add(jtfSocksHost, "");
        jpInternetProxy.add(jlSocksPort, "gap unrel, right");
        jpInternetProxy.add(jtfSocksPort, "wrap");
        jpInternetProxy.add(jrbAutomaticProxyConfig, "left, span, wrap");
        jpInternetProxy.add(jlPacUrl, "gap unrel, skip, right");
        jpInternetProxy.add(jtfPacUrl, "span, wrap push");

        jrbAutomaticProxyConfig.addItemListener(evt -> updateProxyControls());

        jrbManualProxyConfig.addItemListener(evt -> updateProxyControls());

        ProxySelector proxySelector = ProxySelector.getDefault();
        if (proxySelector instanceof SystemProxySelector) {
            jrbSystemProxySettings.setSelected(true);
        } else if (proxySelector instanceof PacProxySelector) {
            jrbAutomaticProxyConfig.setSelected(true);
        } else if (proxySelector instanceof ManualProxySelector) {
            jrbManualProxyConfig.setSelected(true);
        } else {
            jrbNoProxy.setSelected(true);
        }

        return jpInternetProxy;
    }

    private void updateProxyControls() {
        jtfHttpHost.setEnabled(jrbManualProxyConfig.isSelected());
        jtfHttpPort.setEnabled(jrbManualProxyConfig.isSelected());
        jtfHttpsHost.setEnabled(jrbManualProxyConfig.isSelected());
        jtfHttpsPort.setEnabled(jrbManualProxyConfig.isSelected());
        jtfSocksHost.setEnabled(jrbManualProxyConfig.isSelected());
        jtfSocksPort.setEnabled(jrbManualProxyConfig.isSelected());
        jtfPacUrl.setEnabled(jrbAutomaticProxyConfig.isSelected());
    }

    boolean storeProxyPreferences() {
        String title = res.getString("DPreferences.Title");
        // Store current proxy selector - compare with new one to see if default needs updated
        ProxySelector defaultProxySelector = ProxySelector.getDefault();

        // set no proxy
        if (jrbNoProxy.isSelected()) {
            NoProxySelector noProxySelector = new NoProxySelector();
            if (!noProxySelector.equals(defaultProxySelector)) {
                ProxySelector.setDefault(noProxySelector);
            }
        }

        // set system proxy
        if (jrbSystemProxySettings.isSelected()) {
            SystemProxySelector systemProxySelector = new SystemProxySelector();
            if (!systemProxySelector.equals(defaultProxySelector)) {
                ProxySelector.setDefault(systemProxySelector);
            }
        }

        // set manual proxy
        if (jrbManualProxyConfig.isSelected()) {
            String httpHost = jtfHttpHost.getText().trim();
            String httpPortStr = jtfHttpPort.getText().trim();
            String httpsHost = jtfHttpsHost.getText().trim();
            String httpsPortStr = jtfHttpsPort.getText().trim();
            String socksHost = jtfSocksHost.getText().trim();
            String socksPortStr = jtfSocksPort.getText().trim();

            ProxyAddress httpProxyAddress = null;
            ProxyAddress httpsProxyAddress = null;
            ProxyAddress socksProxyAddress = null;

            // Require at least one of the HTTP host or HTTPS host or SOCKS host manual settings
            if ((httpHost.isEmpty()) && (httpsHost.isEmpty()) && (socksHost.isEmpty())) {
                JOptionPane.showMessageDialog(parent, res.getString("DPreferences.ManualConfigReq.message"), title,
                                              JOptionPane.WARNING_MESSAGE);
                return false;
            }

            // check http
            if (!httpHost.isEmpty()) {
                if (!IpAddress.isValidPort(httpPortStr) || httpPortStr.isEmpty()) {
                    JOptionPane.showMessageDialog(parent, res.getString("DPreferences.PortReqHttp.message"), title,
                                                  JOptionPane.WARNING_MESSAGE);
                    return false;
                }
                int httpPort = Integer.parseInt(httpPortStr);
                httpProxyAddress = new ProxyAddress(httpHost, httpPort);
            }

            // check https
            if (!httpsHost.isEmpty()) {
                if (!IpAddress.isValidPort(httpsPortStr) || httpsPortStr.isEmpty()) {
                    JOptionPane.showMessageDialog(parent, res.getString("DPreferences.PortReqHttps.message"), title,
                                                  JOptionPane.WARNING_MESSAGE);
                    return false;
                }
                int httpsPort = Integer.parseInt(httpsPortStr);
                httpsProxyAddress = new ProxyAddress(httpsHost, httpsPort);
            }

            // check socks
            if (!socksHost.isEmpty()) {
                if (!IpAddress.isValidPort(socksPortStr) || socksPortStr.isEmpty()) {
                    JOptionPane.showMessageDialog(parent, res.getString("DPreferences.PortReqSocks.message"), title,
                                                  JOptionPane.WARNING_MESSAGE);
                    return false;
                }
                int socksPort = Integer.parseInt(socksPortStr);
                socksProxyAddress = new ProxyAddress(socksHost, socksPort);
            }
            ManualProxySelector manualProxySelector = new ManualProxySelector(httpProxyAddress, httpsProxyAddress, null,
                                                                              socksProxyAddress);
            if (!manualProxySelector.equals(defaultProxySelector)) {
                ProxySelector.setDefault(manualProxySelector);
            }
        }

        // check automatic proxy
        if (jrbAutomaticProxyConfig.isSelected()) {
            String pacUrl = jtfPacUrl.getText().trim();
            if (pacUrl.isEmpty()) {
                JOptionPane.showMessageDialog(parent, res.getString("DPreferences.PacUrlReq.message"), title,
                                              JOptionPane.WARNING_MESSAGE);
                return false;
            }
            PacProxySelector pacProxySelector;
            try {
                pacProxySelector = new PacProxySelector(new URI(pacUrl));
            } catch (URISyntaxException e) {
                JOptionPane.showMessageDialog(parent, res.getString("DPreferences.PacUrlReq.message"), title,
                                              JOptionPane.WARNING_MESSAGE);
                return false;
            }
            if (!pacProxySelector.equals(defaultProxySelector)) {
                ProxySelector.setDefault(pacProxySelector);
            }
        }
        return true;
    }
}
