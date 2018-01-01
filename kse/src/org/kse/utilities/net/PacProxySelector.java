/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.kse.utilities.io.CopyUtil;

/**
 * Proxy Selector for Proxy Automatic Configuration (PAC).
 *
 */
public class PacProxySelector extends ProxySelector {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/utilities/net/resources");

	private Invocable pacScript;
	private String pacUrl;

	/**
	 * Construct PacProxySelector using an Automatic proxy configuration URL.
	 * Loads the PAC script from the supplied URL.
	 *
	 * @param pacUrl
	 *            Automatic proxy configuration URL
	 */
	public PacProxySelector(String pacUrl) {
		if (pacUrl == null) {
			throw new NullPointerException();
		}

		this.pacUrl = pacUrl;

		// As load and compile of pac scripts is time-consuming we do this on first call to select
	}

	/**
	 * Get a list of proxies for the supplied URI.
	 *
	 * @param uri
	 *            The URI that a connection is required to
	 * @return List of proxies
	 */
	@Override
	public List<Proxy> select(URI uri) {
		// If there are any issues with the PAC return 'no proxy'
		ArrayList<Proxy> proxies = new ArrayList<Proxy>();

		if (pacScript == null) {
			try {
				pacScript = compilePacScript(loadPacScript(pacUrl));
			} catch (PacProxyException ex) {
				ex.printStackTrace();
				proxies.add(Proxy.NO_PROXY);
				return proxies;
			}
		}

		String pacFunctionReturn = null;

		try {
			pacFunctionReturn = (String) pacScript.invokeFunction("FindProxyForURL", uri.toString(), uri.getHost());
		} catch (NoSuchMethodException ex) {
			ex.printStackTrace();
			proxies.add(Proxy.NO_PROXY);
			return proxies;
		} catch (ScriptException ex) {
			ex.printStackTrace();
			proxies.add(Proxy.NO_PROXY);
			return proxies;
		}

		if (pacFunctionReturn == null) {
			proxies.add(Proxy.NO_PROXY);
			return proxies;
		}

		proxies.addAll(parsePacProxies(pacFunctionReturn));

		if (proxies.size() == 0) {
			proxies.add(Proxy.NO_PROXY);
		}

		return proxies;
	}

	private String loadPacScript(String pacUrl) throws PacProxyException {
		URLConnection connection = null;

		// Save existing default proxy selector...
		ProxySelector defaultProxySelector = ProxySelector.getDefault();

		try {
			// ...and set use of no proxy selector. We don't want to try and use any proxy to get the the pac script
			ProxySelector.setDefault(new NoProxySelector());

			URL latestVersionUrl = new URL(pacUrl);
			connection = latestVersionUrl.openConnection();

			try (InputStreamReader isr = new InputStreamReader(connection.getInputStream());
					StringWriter sw = new StringWriter()) {
				CopyUtil.copy(isr, sw);
				return sw.toString();
			}
		} catch (IOException ex) {
			throw new PacProxyException(
					MessageFormat.format(res.getString("NoLoadPacScript.exception.message"), pacUrl), ex);
		} finally {
			// Restore saved default proxy selector
			ProxySelector.setDefault(defaultProxySelector);

			if ((connection != null) && (connection instanceof HttpURLConnection)) {
				((HttpURLConnection) connection).disconnect();
			}
		}
	}

	private Invocable compilePacScript(String pacScript) throws PacProxyException {
		try {
			ScriptEngineManager mgr = new ScriptEngineManager();
			ScriptEngine jsEngine = mgr.getEngineByName("JavaScript");

			Invocable invocale = (Invocable) jsEngine;

			jsEngine.eval(pacScript);
			jsEngine.eval(new InputStreamReader(PacProxySelector.class.getResourceAsStream("pacUtils.js")));

			return invocale;
		} catch (ScriptException ex) {
			throw new PacProxyException(res.getString("NoCompilePacScript.exception.message"), ex);
		}
	}

	private List<Proxy> parsePacProxies(String pacFunctionReturn) {
		ArrayList<Proxy> proxies = new ArrayList<Proxy>();

		// PAC function return delimits different proxies by ';'
		StringTokenizer strTok = new StringTokenizer(pacFunctionReturn, ";");

		while (strTok.hasMoreTokens()) {
			String pacFunctionReturnElement = strTok.nextToken().trim();

			if (pacFunctionReturnElement.length() > 0) {
				Proxy proxy = parsePacProxy(pacFunctionReturnElement);

				if (proxy != null) {
					proxies.add(proxy);
				}
			}
		}

		return proxies;
	}

	private Proxy parsePacProxy(String pacProxy) {
		/*
		 * PAC formats:
		 *
		 * DIRECT Connections should be made directly, without any proxies.
		 *
		 * PROXY host:port The specified proxy should be used.
		 *
		 * SOCKS host:port The specified SOCKS server should be used.
		 *
		 * Where port is not supplied use port 80
		 */

		if (pacProxy.equals("DIRECT")) {
			return Proxy.NO_PROXY;
		}

		String[] split = pacProxy.split(" ", 0);

		if (split.length != 2) {
			return null;
		}

		String proxyTypeStr = split[0];
		String address = split[1];

		Proxy.Type proxyType = null;

		if (proxyTypeStr.equals("PROXY")) {
			proxyType = Proxy.Type.HTTP;
		} else if (proxyTypeStr.equals("SOCKS")) {
			proxyType = Proxy.Type.SOCKS;
		}

		if (proxyType == null) {
			return null;
		}

		split = address.split(":", 0);
		String host = null;
		int port = 80;

		if (split.length == 1) {
			host = split[0];
		} else if (split.length == 2) {
			host = split[0];

			try {
				port = Integer.parseInt(split[1]);
			} catch (NumberFormatException ex) {
				return null;
			}
		} else {
			return null;
		}

		return new Proxy(proxyType, new InetSocketAddress(host, port));
	}

	/**
	 * Connection failed. Do nothing.
	 *
	 * @param uri
	 *            The URI that the proxy at socketAddress failed to serve
	 * @param socketAddress
	 *            The socket address of the proxy/SOCKS server
	 * @param ioException
	 *            The I/O exception thrown when the connect failed
	 */
	@Override
	public void connectFailed(URI uri, SocketAddress socketAddress, IOException ioException) {
		/*
		 * Do nothing. Documentation of base class ProxySelector suggests that
		 * this method may be used to affect what the select method returns.
		 * This is not relevant to us.
		 */
	}

	/**
	 * Get Automatic proxy configuration URL.
	 *
	 * @return PAC URL
	 */
	public String getPacUrl() {
		return pacUrl;
	}

	/**
	 * Is this PacProxySelector object equal to another object?
	 *
	 * @param object
	 *            Object to compare PacProxySelector with.
	 * @return true if the equal, false otherwise.
	 */
	@Override
	public boolean equals(Object object) {
		if (object == this) {
			return true;
		}

		if (!(object instanceof PacProxySelector)) {
			return false;
		}

		PacProxySelector cmpPacProxySelector = (PacProxySelector) object;

		return this.getPacUrl().equals(cmpPacProxySelector.getPacUrl());
	}
}
