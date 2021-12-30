package org.kse.utilities.ssl.starttls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Implementation of STARTTLS for IMAP
 */
class StartTlsImap {

	// IMAP uses Windows line separators, see RFC 3501
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
	StartTlsImap(String host, int port) {
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

		// dialog for STARTTLS, see RFC 3501 section 6.2.1.
		sendCommand("a001 CAPABILITY");
		readLines("a001 OK ");
		sendCommand("a002 STARTTLS");
		readLines("a002 OK ");

		return socket;
	}


	private void readLines(String expectedAnswer) throws IOException {
		String line;

		while ((line = br.readLine()) != null) {

			// errors are indicated by  "NO" or "BAD", see RFC 3501
			if (line.contains("NO") || line.contains("BAD")) {
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
