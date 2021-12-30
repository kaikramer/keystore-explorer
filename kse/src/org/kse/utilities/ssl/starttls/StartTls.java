package org.kse.utilities.ssl.starttls;

import java.io.IOException;
import java.net.Socket;

import org.kse.utilities.ssl.ConnectionType;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public abstract class StartTls {

	public static Socket startTls(ConnectionType type, String host, int port) throws IOException {
		switch (type) {
		case STARTTLS_SMTP:
			StartTlsSmtp startTlsSmtp = new StartTlsSmtp(host, port);
			return startTlsSmtp.doStartTls();
		case STARTTLS_IMAP:
			StartTlsImap startTlsImap = new StartTlsImap(host, port);
			return startTlsImap.doStartTls();
		case STARTTLS_POSTGRES:
			StartTlsPostgreSQL startTlsPostgreSQL = new StartTlsPostgreSQL(host, port);
			return startTlsPostgreSQL.doStartTls();
		case GENERIC_TLS:
		case HTTPS:
		default:
			throw new NotImplementedException();
		}
	}

	protected abstract Socket doStartTls();
}
