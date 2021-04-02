/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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

import java.net.InetSocketAddress;

/**
 * Proxy address: host name and port.
 *
 */
public class ProxyAddress {
	private String host;
	private int port;

	/**
	 * Construct proxy.
	 *
	 * @param host
	 *            Proxy host name
	 * @param port
	 *            Proxy port number
	 */
	public ProxyAddress(String host, int port) {
		if (host == null) {
			throw new NullPointerException();
		}

		this.host = host;
		this.port = port;
	}

	/**
	 * Get proxy address as an InetSocketAddress.
	 *
	 * @return InetSocketAddress
	 */
	public InetSocketAddress getInetSocketAddress() {
		return new InetSocketAddress(host, port);
	}

	/**
	 * Get proxy host name.
	 *
	 * @return Proxy host name
	 */
	public String getHost() {
		return host;
	}

	/**
	 * Get proxy port number.
	 *
	 * @return Proxy port number
	 */
	public int getPort() {
		return port;
	}

	/**
	 * Is this ProxyAddress object equal to another object?
	 *
	 * @param object
	 *            Object to compare ProxyAddress with.
	 * @return true if the equal, false otherwise.
	 */
	@Override
	public boolean equals(Object object) {
		if (object == this) {
			return true;
		}

		if (!(object instanceof ProxyAddress)) {
			return false;
		}

		ProxyAddress cmpProxyAddress = (ProxyAddress) object;

		if (!this.getHost().equals(cmpProxyAddress.getHost())) {
			return false;
		}

		return (this.getPort() == cmpProxyAddress.getPort());
	}
}
