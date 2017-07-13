package net.sf.keystore_explorer.version;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.kse.version.Version;
import org.kse.version.VersionException;

public class VersionTest {

	@Test
	public void testVersionString() {

		new Version("5.2.2");
		new Version("5.2.2\n");

		try {
			new Version("");
			new Version("a");
			fail();
		} catch (VersionException e) {
			// expected exception
		}
	}

	@Test
	public void testMajorMinorVersion() {
		assertEquals(1, new Version("1").getMajor());
		assertEquals(1, new Version("01").getMajor());
		assertEquals(1, new Version("1.2").getMajor());
		assertEquals(1, new Version("1.2.3").getMajor());

		assertEquals(2, new Version("1.2").getMinor());
		assertEquals(2, new Version("1.2.3").getMinor());
		assertEquals(0, new Version("1").getMinor());
		assertEquals(0, new Version("1.0").getMinor());
		assertEquals(0, new Version("1.0.0").getMinor());

		assertEquals(3, new Version("1.2.3").getBugfix());
		assertEquals(3, new Version("1.2.3.4").getBugfix());
		assertEquals(0, new Version("1").getBugfix());
		assertEquals(0, new Version("1.2").getBugfix());
		assertEquals(0, new Version("1.2.0").getBugfix());
	}

	@Test
	public void testCompare() {
		assertTrue(new Version("1").compareTo(new Version("2")) < 0);
		assertTrue(new Version("1").compareTo(new Version("1")) == 0);
		assertTrue(new Version("2").compareTo(new Version("1")) > 0);

		assertTrue(new Version("1.2").compareTo(new Version("1.3")) < 0);
		assertTrue(new Version("1.2").compareTo(new Version("1.2")) == 0);
		assertTrue(new Version("1.3").compareTo(new Version("1.2")) > 0);

		assertTrue(new Version("1").compareTo(new Version("1.1")) < 0);
		assertTrue(new Version("1.1").compareTo(new Version("1.1.1")) < 0);
		assertTrue(new Version("1.1.1").compareTo(new Version("1.1.1.1")) < 0);


		assertTrue(new Version("1").compareTo(new Version("1.0.0")) == 0);
		assertTrue(new Version("1.1").compareTo(new Version("1.1.0")) == 0);
		assertTrue(new Version("1.1.1").compareTo(new Version("1.1.1.0")) == 0);

		assertTrue(new Version("9").compareTo(new Version("10.0.0")) < 0);
		assertTrue(new Version("9.20.20.20").compareTo(new Version("10.0.0")) < 0);
		assertTrue(new Version("9.9.9.9").compareTo(new Version("10")) < 0);
		assertTrue(new Version("9.9.1").compareTo(new Version("9.10.3")) < 0);
		assertTrue(new Version("9.1.2").compareTo(new Version("9.1.2.1")) < 0);
	}
}