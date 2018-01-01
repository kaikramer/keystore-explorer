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
package org.kse.crypto.signing;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.kse.crypto.digest.DigestType;

public class TimeStampingClient {

	/**
	 * Get RFC 3161 timeStampToken.
	 *
	 * @param tsaUrl Location of TSA
	 * @param data The data to be time-stamped
	 * @param hashAlg The algorithm used for generating a hash value of the data to be time-stamped
	 * @return encoded, TSA signed data of the timeStampToken
	 * @throws IOException
	 */
	public static byte[] getTimeStampToken(String tsaUrl, byte[] data, DigestType hashAlg) throws IOException {

		TimeStampResponse response = null;
		try {

			// calculate hash value
			MessageDigest digest = MessageDigest.getInstance(hashAlg.jce());
			byte[] hashValue = digest.digest(data);

			// Setup the time stamp request
			TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
			tsqGenerator.setCertReq(true);
			BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
			TimeStampRequest request = tsqGenerator.generate(new ASN1ObjectIdentifier(hashAlg.oid()), hashValue, nonce);
			byte[] requestBytes = request.getEncoded();

			// send http request
			byte[] respBytes = queryServer(tsaUrl, requestBytes);

			// process response
			response = new TimeStampResponse(respBytes);

			// validate communication level attributes (RFC 3161 PKIStatus)
			response.validate(request);
			PKIFailureInfo failure = response.getFailInfo();
			int value = failure == null ? 0 : failure.intValue();
			if (value != 0) {
				throw new IOException("Server returned error code: " + String.valueOf(value));
			}
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		} catch (TSPException e) {
			throw new IOException(e);
		}

		// extract the time stamp token
		TimeStampToken tsToken = response.getTimeStampToken();
		if (tsToken == null) {
			throw new IOException("TSA returned no time stamp token: " + response.getStatusString());
		}

		return tsToken.getEncoded();
	}

	/**
	 * Get timestamp token (HTTP communication)
	 *
	 * @return TSA response, raw bytes (RFC 3161 encoded)
	 * @throws IOException
	 */
	private static byte[] queryServer(String tsaUrl, byte[] requestBytes) throws IOException {

		// Install the all-trusting trust manager
		SSLContext sc;
		try {
			sc = SSLContext.getInstance("SSL");
			sc.init(null, new TrustManager[] {new X509TrustManager() {
				@Override
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}
				@Override
				public void checkClientTrusted(X509Certificate[] certs, String authType) {
				}
				@Override
				public void checkServerTrusted(X509Certificate[] certs, String authType) {
				}
			}
			}, new java.security.SecureRandom());
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		} catch (KeyManagementException e) {
			throw new IOException(e);
		}
		SSLSocketFactory defaultSSLSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

		try {
			URL url = new URL(tsaUrl);
			URLConnection con = url.openConnection();
			con.setDoInput(true);
			con.setDoOutput(true);
			con.setUseCaches(false);
			con.setRequestProperty("Content-Type", "application/timestamp-query");
			con.setRequestProperty("Content-Transfer-Encoding", "binary");

			OutputStream out = con.getOutputStream();
			out.write(requestBytes);
			out.close();

			InputStream is = con.getInputStream();
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			int bytesRead = 0;
			while ((bytesRead = is.read(buffer, 0, buffer.length)) >= 0) {
				baos.write(buffer, 0, bytesRead);
			}
			byte[] respBytes = baos.toByteArray();

			String encoding = con.getContentEncoding();
			if (encoding != null && encoding.equalsIgnoreCase("base64")) {
				respBytes = Base64.decode(new String(respBytes));
			}
			return respBytes;

		} finally {
			// restore default trust manager
			HttpsURLConnection.setDefaultSSLSocketFactory(defaultSSLSocketFactory);
		}
	}
}
