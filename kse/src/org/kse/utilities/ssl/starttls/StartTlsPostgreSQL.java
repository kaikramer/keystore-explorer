package org.kse.utilities.ssl.starttls;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

/**
 * Implementation of STARTTLS for PostgreSQL
 */
class StartTlsPostgreSQL {

	private DataInputStream dis;
	private DataOutputStream dos;
	private String host;
	private int port;

	/**
	 * c-tor
	 *
	 * @param host SMTP server
	 * @param port Port
	 */
	StartTlsPostgreSQL(String host, int port) {
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
		dos = new DataOutputStream(socket.getOutputStream());
		dis = new DataInputStream(socket.getInputStream());

		dos.write(new byte[] { 0, 0, 0, 8, 4, (byte) 210, 22, 47 });
		byte response = (byte) dis.read();
		if (response != 'S') {
			throw new IOException("STARTTLS not accepted");
		}

		return socket;
	}

}
