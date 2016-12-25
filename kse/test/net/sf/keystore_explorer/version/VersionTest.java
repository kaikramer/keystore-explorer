package net.sf.keystore_explorer.version;

import static org.junit.Assert.*;

import org.junit.Test;

public class VersionTest {

	@Test
	public void testVersionString() {
		new Version("5.2.2\n");
	}

}
