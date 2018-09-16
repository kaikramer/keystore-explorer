package org.kse.crypto.signing;

import java.io.IOException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.kse.crypto.digest.DigestType;
import org.kse.utilities.net.URLs;

class TimeStampingClientTest {

	private static final byte[] DATA = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

	@ParameterizedTest
	@MethodSource("tsaUrls")
	public void testTsaUrls(String tsaUrl) throws IOException {
		TimeStampingClient.getTimeStampToken(tsaUrl, DATA, DigestType.SHA1);
	}

	static String[] tsaUrls() {
		return URLs.TSA_URLS;
	}
}
