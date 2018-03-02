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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

public class RetrieveSslInfosHandshakeListener implements HandshakeCompletedListener {

	private SslConnectionInfos sslConnectionInfos = new SslConnectionInfos();

	@Override
	public void handshakeCompleted(HandshakeCompletedEvent event) {

		SSLSession session = event.getSession();
		sslConnectionInfos.setPeerHost(session.getPeerHost());
		sslConnectionInfos.setPeerPort(session.getPeerPort());
		sslConnectionInfos.setProtocol(session.getProtocol());
		sslConnectionInfos.setCipherSuite(session.getCipherSuite());

		Certificate[] locChain = session.getLocalCertificates();
		if (locChain != null) {
			X509Certificate[] clientCertificates = Arrays.copyOf(locChain, locChain.length, X509Certificate[].class);
			sslConnectionInfos.setClientCertificates(clientCertificates);
		}

		try {
			Certificate[] chain = session.getPeerCertificates();
			if (chain != null) {
				X509Certificate[] serverCertificates = Arrays.copyOf(chain, chain.length, X509Certificate[].class);
				sslConnectionInfos.setServerCertificates(serverCertificates);
			}
		} catch (SSLPeerUnverifiedException e) {
			// do nothing
		}
	}

	public SslConnectionInfos getSslConnectionInfos() {
		return sslConnectionInfos;
	}
}