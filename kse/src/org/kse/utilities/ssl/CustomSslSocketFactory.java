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
package org.kse.utilities.ssl;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Custom SSL factory that adds a HandshakeCompletedListener to the SSLSocket.
 *
 */
public class CustomSslSocketFactory extends SSLSocketFactory {

	private final SSLSocketFactory sslSocketFactory;

	private HandshakeCompletedListener handshakeListener;

	private boolean sniEnabled;

	/**
	 * Constructor
	 *
	 * @param sslSocketFactory The actual SSLSocketFactory (used by this class)
	 * @param handshakeListener The class that handles "handshake completed" events
	 */
	public CustomSslSocketFactory(SSLSocketFactory sslSocketFactory, HandshakeCompletedListener handshakeListener,
			boolean sniEnabled) {
		this.sslSocketFactory = sslSocketFactory;
		this.handshakeListener = handshakeListener;
		this.sniEnabled = sniEnabled;
	}

	@Override
	public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {

		SSLSocket socket = (SSLSocket) this.sslSocketFactory.createSocket(s, host, port, autoClose);

		if (!sniEnabled) {
			disableSNI(socket);
		}

		if (this.handshakeListener != null) {
			socket.addHandshakeCompletedListener(this.handshakeListener);
		}

		return socket;
	}

	private void disableSNI(SSLSocket socket) {
		// effectively disable SNI by passing an empty server name list (works only in Java 8 or higher)
		SSLParameters sslParameters = socket.getSSLParameters();
		Method setServerNamesMethod;
		try {
			setServerNamesMethod = sslParameters.getClass().getMethod("setServerNames", List.class);
			setServerNamesMethod.invoke(sslParameters, new ArrayList<Object>());
			socket.setSSLParameters(sslParameters);
		} catch (Exception e) {
			// Java 6/7, nothing we can do here (setting jsse.enableSNIExtension wouldn't work here anymore)
		}
	}

	@Override
	public Socket createSocket(String paramString, int paramInt) throws IOException, UnknownHostException {

		SSLSocket socket = (SSLSocket) this.sslSocketFactory.createSocket(paramString, paramInt);

		if (this.handshakeListener != null) {
			socket.addHandshakeCompletedListener(this.handshakeListener);
		}

		return socket;
	}

	@Override
	public Socket createSocket(String paramString, int paramInt1, InetAddress paramInetAddress, int paramInt2)
			throws IOException, UnknownHostException {

		SSLSocket socket = (SSLSocket) this.sslSocketFactory.createSocket(paramString, paramInt1, paramInetAddress,
				paramInt2);

		if (this.handshakeListener != null) {
			socket.addHandshakeCompletedListener(this.handshakeListener);
		}

		return socket;
	}

	@Override
	public Socket createSocket(InetAddress paramInetAddress, int paramInt) throws IOException {

		SSLSocket socket = (SSLSocket) this.sslSocketFactory.createSocket(paramInetAddress, paramInt);

		if (this.handshakeListener != null) {
			socket.addHandshakeCompletedListener(this.handshakeListener);
		}

		return socket;
	}

	@Override
	public Socket createSocket(InetAddress paramInetAddress1, int paramInt1, InetAddress paramInetAddress2,
			int paramInt2) throws IOException {

		SSLSocket socket = (SSLSocket) this.sslSocketFactory.createSocket(paramInetAddress1, paramInt1,
				paramInetAddress2, paramInt2);

		if (this.handshakeListener != null) {
			socket.addHandshakeCompletedListener(this.handshakeListener);
		}

		return socket;
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return this.sslSocketFactory.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return this.sslSocketFactory.getSupportedCipherSuites();
	}

}