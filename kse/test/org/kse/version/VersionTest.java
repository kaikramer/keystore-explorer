package org.kse.version;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class VersionTest {

	@ParameterizedTest
	@CsvSource({
		"5",
		"5.0",
		"5.0.0",
		"5.2.2",
		"5.2.2\n",
		"5.3",
	})
	public void testVersionString(String verString) {
		new Version(verString);
	}


	@ParameterizedTest
	@CsvSource({
		"''",
		"a",
		"ea",
		"1-0-0",
	})
	public void invalidVersion(String verString) {
		assertThrows(VersionException.class, () -> new Version(verString));
	}

	@ParameterizedTest
	@CsvSource({
		"01, 		1, 0, 0",
		"1, 		1, 0, 0",
		"1.0, 		1, 0, 0",
		"1.0.0,		1, 0, 0",
		"1.2, 		1, 2, 0",
		"1.2.3, 	1, 2, 3",
		"1.2.3, 	1, 2, 3",
		"1.2.3.4, 	1, 2, 3",
	})
	public void testMajorMinorVersion(String versionString, int major, int minor, int bugfix) {
		assertEquals(major, new Version(versionString).getMajor());
		assertEquals(minor, new Version(versionString).getMinor());
		assertEquals(bugfix, new Version(versionString).getBugfix());
	}

	@ParameterizedTest
	@CsvSource({
		"01, 		1, 		0",
		"1, 		1, 		0",
		"1.0, 		1, 		0",
		"1.0.0,		1, 		0",
		"1.0, 		1.0, 	0",
		"1.0.0,		1.0.0, 	0",
		"1.2, 		1, 		1",
		"1.2, 		1.3, 	-1",
		"1.2.3, 	1, 		1",
		"1.2.3.4, 	1, 		1",
		"1.3.1, 	1.3,	1",
		"1.2.3, 	1.3,	-1",
		"1.2.3.4, 	1.3, 	-1",
		"1.3.1, 	1.3.2, 	-1",
		"1.3.2, 	1.3.2.1,-1",
		"9.9.9.9,	10.0.0, -1",
		"9.20.20,	10.0.0, -1",
	})
	public void testCompare(String version1, String version2, int resultSignum) {
		assertEquals(Integer.signum(new Version(version1).compareTo(new Version(version2))), resultSignum);
	}
}