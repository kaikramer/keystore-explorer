package org.kse.utilities.ssl.starttls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Implementation of STARTTLS for SMTP
 */
class StartTlsSmtp {

	// SMTP uses Windows line separators, see RFC 5321 section 2.3.8
	private static final String CRLF = "\r\n";

	private BufferedReader br;
	private OutputStreamWriter osw;
	private String host;
	private int port;

	/**
	 * c-tor
	 *
	 * @param host SMTP server
	 * @param port Port
	 */
	StartTlsSmtp(String host, int port) {
		this.host = host;
		this.port = port;
	}

	/**
	 * Init SSL connection with STARTTLS command on unencrypted socket.
	 *
	 * @return Non-SSL socket where STARTTLS command was accepted by SMTP server
	 * @throws IOException if communication failed
	 */
	protected Socket doStartTls() throws IOException {

		Socket socket = new Socket(host, port);
		osw = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII);
		br = new BufferedReader(new InputStreamReader(socket.getInputStream()));

		// dialog for STARTTLS, see RFC 3207
		readLines("220 ");
		sendCommand("EHLO " + host);
		readLines("250 ");
		sendCommand("STARTTLS");
		readLines("220 ");

		return socket;
	}


	private void readLines(String expectedAnswer) throws IOException {
		String line;

		while ((line = br.readLine()) != null) {

			// errors are indicated by the server with a code like "4yz" or "5yz", see RFC 5321 section 4.2.1.
			if (line.startsWith("4") || line.startsWith("5")) {
				throw new IOException(line);
			}

			if (line.startsWith(expectedAnswer)) {
				break;
			}

			// just ignore other lines
		}
	}


	private void sendCommand(String command) throws IOException {
		osw.write((command + CRLF));
		osw.flush();
	}
}
