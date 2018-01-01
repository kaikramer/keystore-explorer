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
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.kse.crypto.CryptoException;

public class SslUtils {

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/utilities/ssl/resources");

	/**
	 * Load certificates from an SSL connection.
	 *
	 * @param host
	 *            Connection host
	 * @param port
	 *            Connection port
	 * @param keyStore
	 *            KeyStore with a key pair for SSL client authentication
	 * @param password
	 *            The password for the KeyStore
	 * @return SSL infos
	 * @throws CryptoException
	 *             Problem encountered while loading the certificate(s)
	 * @throws IOException
	 *             An I/O error occurred
	 */
	public static SslConnectionInfos readSSLConnectionInfos(String host, int port, KeyStore keyStore, char[] password)
			throws CryptoException, IOException {

		URL url = new URL(MessageFormat.format("https://{0}:{1}/", host, "" + port));
		HttpsURLConnection connection = null;

		System.setProperty("javax.net.debug", "ssl");

		try {
			connection = (HttpsURLConnection) url.openConnection();

			// create a key manager for client authentication
			X509KeyManager km = null;
			if (keyStore != null) {
				KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
				keyManagerFactory.init(keyStore, password);
				for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
					if (keyManager instanceof X509KeyManager) {
						km = (X509KeyManager) keyManager;
						break;
					}
				}
			}

			// We are only interested in getting the SSL certificates even if they are invalid
			// either in and of themselves or for the host name they are associated with

			// 1) set connection's SSL Socket factory to have a very trusting trust manager
			SSLContext context = SSLContext.getInstance("TLS");
			X509TrustingManager tm = new X509TrustingManager();
			context.init(new KeyManager[] { km }, new TrustManager[] { tm }, null);

			// 2) set a host name verifier that always verifies the host name
			connection.setHostnameVerifier(new HostnameVerifier() {
				@Override
				public boolean verify(String hostname, SSLSession sslSession) {
					return true;
				}
			});

			// register our handshake completed listener in order to retrieve SSL connection infos later
			SSLSocketFactory factory = context.getSocketFactory();
			RetrieveSslInfosHandshakeListener handshakeListener = new RetrieveSslInfosHandshakeListener();
			boolean sniEnabled = true;
			connection.setSSLSocketFactory(new CustomSslSocketFactory(factory, handshakeListener, sniEnabled));

			try {
				connection.connect();
			} catch (SSLProtocolException e) {
				// handle server misconfiguration (works only in Java 8 or higher)
				if (e.getMessage().contains("unrecognized_name")) {
					sniEnabled = false;
					connection.setSSLSocketFactory(new CustomSslSocketFactory(factory, handshakeListener, sniEnabled));
					connection.connect();
				} else {
					throw e;
				}
			}

			// this is necessary in order to cause a handshake exception when the client cert is not accepted
			if (keyStore != null) {
				connection.getResponseMessage();
			}

			SslConnectionInfos sslConnectionInfos = handshakeListener.getSslConnectionInfos();
			sslConnectionInfos.setSniEnabled(sniEnabled);

			return sslConnectionInfos;

		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoLoadCertificate.exception.message"), ex);
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	/**
	 * Implementation of the X509TrustManager. In this implementation we
	 * always trust the server as we are only interested in getting its
	 * certificates for examination.
	 */
	private static class X509TrustingManager implements X509TrustManager {
		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}
		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			throw new UnsupportedOperationException();
		}
		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}
	}
}
