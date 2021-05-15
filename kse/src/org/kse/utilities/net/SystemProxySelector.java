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

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.List;

/**
 * Proxy Selector for system proxy settings.
 *
 */
public class SystemProxySelector extends ProxySelector {
	private static ProxySelector systemProxySelector;

	@Override
	public List<Proxy> select(URI uri) {
		return getSystemProxySelector().select(uri);
	}

	@Override
	public void connectFailed(URI uri, SocketAddress socketAddress, IOException ioException) {
		getSystemProxySelector().connectFailed(uri, socketAddress, ioException);
	}

	@Override
	public boolean equals(Object object) {
		if (object == this) {
			return true;
		}

		if (!(object instanceof SystemProxySelector)) {
			return false;
		}

		return true;
	}

	public static ProxySelector getSystemProxySelector() {
		return systemProxySelector;
	}

	public static void setSystemProxySelector(ProxySelector systemProxySelector) {
		SystemProxySelector.systemProxySelector = systemProxySelector;
	}
}
