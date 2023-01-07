package org.kse.utilities.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.of;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.stream.Stream;

import org.bouncycastle.util.IPAddress;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class PacHelperFunctionsTest {

    private static String myHostName;
    private static String myIpAddress;

    @BeforeAll
    static void beforeAll() throws UnknownHostException {
        // NOTE: some tests require that the unit tests are executed in an environment with working name resolution!
        myHostName = Inet4Address.getLocalHost().getHostName();
        myIpAddress = Inet4Address.getLocalHost().getHostAddress();
    }

    @ParameterizedTest
    @CsvSource({
            "www.netscape.com, .netscape.com, true",
            "test.netscape.com, .netscape.com, true",
            "www.netscape.com, netscape.com, true",
            "www, .netscape.com, false",
            "www.mcom.com, .netscape.com, false",
    })
    void dnsDomainIs(String host, String domain, boolean result) {
        assertThat(PacHelperFunctions.dnsDomainIs(host, domain)).isEqualTo(result);
    }

    @ParameterizedTest
    @CsvSource({
            "www, 0",
            "netscape.com, 1",
            "www.netscape.com, 2",
            "sub1.sub2.netscape.com, 3",
    })
    void dnsDomainLevels(String host, int result) {
        assertThat(PacHelperFunctions.dnsDomainLevels(host)).isEqualTo(result);
    }

    @ParameterizedTest
    @MethodSource
    void dnsResolve(String hostName, String expectedIpAddress) {
        assertThat(PacHelperFunctions.dnsResolve(hostName)).isEqualTo(expectedIpAddress);
    }

    private static Stream<Arguments> dnsResolve() {
        return Stream.of(
                of(myHostName, myIpAddress),
                of("thishostdoesnotexist", "")
                );
    }

    @Test
    void myIpAddress() {
        assertThat(IPAddress.isValid(PacHelperFunctions.myIpAddress())).isTrue();
    }

    @ParameterizedTest
    @MethodSource
    void isResolvable(String hostName, boolean expectedResult) {
        assertThat(PacHelperFunctions.isResolvable(hostName)).isEqualTo(expectedResult);
    }

    private static Stream<Arguments> isResolvable() {
        return Stream.of(
                of(myHostName, true),
                of("thishostdoesnotexist", false)
        );
    }

    @ParameterizedTest
    @CsvSource({
            "198.95.249.79, 198.95.249.79, 255.255.255.255, true",
            "198.95.249.78, 198.95.249.79, 255.255.255.255, false",
            "198.95.249.80, 198.95.249.79, 255.255.255.255, false",
            "198.95.0.0, 198.95.0.0, 255.255.0.0, true",
            "198.95.0.1, 198.95.0.0, 255.255.0.0, true",
            "198.95.1.1, 198.95.0.0, 255.255.0.0, true",
            "198.95.255.1, 198.95.0.0, 255.255.0.0, true",
            "198.95.255.255, 198.95.0.0, 255.255.0.0, true",
            "198.94.0.0, 198.95.0.0, 255.255.0.0, false",

            // some general error cases
            "256.0.0.0, 0.0.0.0, 0.0.0.0, false",
            "0.256.0.0, 0.0.0.0, 0.0.0.0, false",
            "0.0.256.0, 0.0.0.0, 0.0.0.0, false",
            "0.0.0.256, 0.0.0.0, 0.0.0.0, false",
            "0.0.0.0.0, 0.0.0.0, 0.0.0.0, false",
            "0.0.0.0, 256.0.0.0, 0.0.0.0, false",
            "0.0.0.0, 256.0.0.0, 256.0.0.0, false",
    })
    void isInNet(String host, String pattern, String mask, boolean result) {
        assertThat(PacHelperFunctions.isInNet(host, pattern, mask)).isEqualTo(result);
    }

    @ParameterizedTest
    @CsvSource({
            "www, true",
            "localhost, true",
            "netscape.com, false",
            "www.netscape.com, false",
    })
    void isPlainHostName(String host, boolean result) {
        assertThat(PacHelperFunctions.isPlainHostName(host)).isEqualTo(result);
    }

    @ParameterizedTest
    @CsvSource({
            "www.netscape.com, www.netscape.com, true",
            "www, www.netscape.com, true",
            "home.netscape.com, www.netscape.com, false",
            "www.netscape, www.netscape.com, false",
            "www.mcom.com, www.netscape.com, false",

    })
    void localHostOrDomainIs(String host, String domain, boolean result) {
        assertThat(PacHelperFunctions.localHostOrDomainIs(host, domain)).isEqualTo(result);
    }

    @ParameterizedTest
    @CsvSource({
            "http://home.netscape.com/people/ari/index.html, */ari/*, true",
            "http://home.netscape.com/people/montulli/index.html, */ari/*, false"
    })
    void shExpMatch(String str, String shexp, boolean result) {
        assertThat(PacHelperFunctions.shExpMatch(str, shexp)).isEqualTo(result);
    }

    @ParameterizedTest
    @MethodSource
    void dateRange(String currentDateTime, String offset, Object[] args, boolean expectedResult) {

        // set clock to a fixed value in order to have consistent test results regardless of actual date/time/timezone
        setClock(currentDateTime, offset);

        assertThat(PacHelperFunctions.dateRange(args)).isEqualTo(expectedResult);
    }

    private static Stream<Arguments> dateRange() {
        return Stream.of(
                // missing parameters
                of("2022-05-23T12:34:56Z", "+02:00", new Object[0], false),
                of("2022-05-23T12:34:56Z", "+02:00", args("GMT"), false),

                // 1 argument: year
                of("2022-05-23T12:34:56Z", "+02:00", args(2022), true),
                of("2021-12-31T22:00:00Z", "+02:00", args(2022), true),
                of("2022-12-31T21:59:59Z", "+02:00", args(2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(2021), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(2023), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(2022, "GMT"), true),
                of("2022-01-01T00:00:00Z", "+00:00", args(2022, "GMT"), true),
                of("2022-12-12T23:59:59Z", "+00:00", args(2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(2021, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(2023, "GMT"), false),

                // 1 argument: month
                of("2022-01-23T12:34:56Z", "+02:00", args("JAN"), true),
                of("2022-02-23T12:34:56Z", "+02:00", args("FEB"), true),
                of("2022-03-23T12:34:56Z", "+02:00", args("MAR"), true),
                of("2022-04-23T12:34:56Z", "+02:00", args("APR"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("MAY"), true),
                of("2022-06-23T12:34:56Z", "+02:00", args("JUN"), true),
                of("2022-07-23T12:34:56Z", "+02:00", args("JUL"), true),
                of("2022-08-23T12:34:56Z", "+02:00", args("AUG"), true),
                of("2022-09-23T12:34:56Z", "+02:00", args("SEP"), true),
                of("2022-10-23T12:34:56Z", "+02:00", args("OCT"), true),
                of("2022-11-23T12:34:56Z", "+02:00", args("NOV"), true),
                of("2022-12-23T12:34:56Z", "+02:00", args("DEC"), true),
                of("2022-04-30T22:00:00Z", "+02:00", args("MAY"), true),
                of("2022-05-31T21:59:59Z", "+02:00", args("MAY"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("APR"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("JUN"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("MAY", "GMT"), true),
                of("2022-05-01T00:00:00Z", "+00:00", args("MAY", "GMT"), true),
                of("2022-05-31T23:59:59Z", "+00:00", args("MAY", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("APR", "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("JUN", "GMT"), false),

                // 1 argument: day
                of("2022-05-23T12:34:56Z", "+02:00", args(23), true),
                of("2022-05-22T22:00:00Z", "+02:00", args(23), true),
                of("2022-05-23T21:59:59Z", "+02:00", args(23), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(22), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(24), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(23, "GMT"), true),
                of("2022-05-23T00:00:00Z", "+00:00", args(23, "GMT"), true),
                of("2022-05-23T23:59:59Z", "+00:00", args(23, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(22, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(24, "GMT"), false),

                // 2 arguments: year1/2
                of("2022-05-23T12:34:56Z", "+02:00", args(2022, 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(2021, 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(2022, 2023), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(2020, 2021), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(2023, 2024), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(2022, 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(2021, 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(2022, 2023, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(2021, 2021, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(2023, 2023, "GMT"), false),

                // 2 arguments: month1/2
                of("2022-05-23T12:34:56Z", "+02:00", args("MAY", "MAY"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("OCT", "AUG"), false), // TODO no rollover?!
                of("2022-05-23T12:34:56Z", "+02:00", args("APR", "MAY"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("MAY", "JUN"), true),
                of("2022-04-30T22:00:00Z", "+02:00", args("APR", "MAY"), true),
                of("2022-05-31T21:59:59Z", "+02:00", args("MAY", "JUN"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("MAR", "APR"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("JUN", "JUL"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("JUN", "APR"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("MAY", "MAY", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("MAR", "APR", "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("JUN", "JUL", "GMT"), false),

                // 2 arguments: day1/2
                of("2022-05-23T12:34:56Z", "+02:00", args(23, 23), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(22, 23), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(23, 24), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(20, 25), true),
                of("2022-05-22T22:00:00Z", "+02:00", args(23, 24), true),
                of("2022-05-23T21:59:59Z", "+02:00", args(22, 23), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(22, 22), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(24, 25), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(20, 22), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(23, 23, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(22, 23, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(23, 24, "GMT"), true),
                of("2022-05-23T00:00:00Z", "+00:00", args(23, 24, "GMT"), true),
                of("2022-05-23T23:59:59Z", "+00:00", args(22, 23, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(24, 24, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(24, 27, "GMT"), false),

                // 4 arguments: day1/month1 and day2/month2
                of("2022-05-23T12:34:56Z", "+02:00", args(23, "MAY", 23, "MAY"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(23, "MAY", 24, "MAY"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(22, "MAY", 23, "MAY"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, "APR", 1, "JUN"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, "JAN", 1, "DEC"), true),
                of("2022-05-22T22:00:00Z", "+02:00", args(23, "MAY", 24, "MAY"), true),
                of("2022-05-23T21:59:59Z", "+02:00", args(22, "MAY", 23, "MAY"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(22, "MAY", 22, "MAY"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, "MAR", 1, "APR"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, "JUN", 1, "APR"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(23, "MAY", 23, "MAY", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(23, "MAY", 24, "MAY", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(22, "MAY", 23, "MAY", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "APR", 1, "JUN", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "JAN", 1, "DEC", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(22, "MAY", 22, "MAY", "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "MAR", 1, "APR", "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "JUN", 1, "APR", "GMT"), false),

                // 4 arguments: month1/year1 and month2/year2
                of("2022-05-23T12:34:56Z", "+02:00", args("MAY", 2022, "MAY", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("APR", 2022, "MAY", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("MAY", 2022, "JUN", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("MAY", 2021, "MAY", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("MAY", 2022, "MAY", 2023), true),
                of("2022-04-30T22:00:00Z", "+02:00", args("MAY", 2022, "JUN", 2022), true),
                of("2022-05-31T21:59:59Z", "+02:00", args("APR", 2022, "MAY", 2022), true),
                of("2022-04-30T21:59:59Z", "+02:00", args("MAY", 2022, "JUN", 2022), false),
                of("2022-05-31T22:00:00Z", "+02:00", args("APR", 2022, "MAY", 2022), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("APR", 2022, "APR", 2022), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("JUN", 2022, "JUN", 2022), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("MAY", 2021, "MAY", 2021), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("MAY", 2022, "MAY", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("APR", 2022, "MAY", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("MAY", 2022, "JUN", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("MAY", 2021, "MAY", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("MAY", 2022, "MAY", 2023, "GMT"), true),
                of("2022-05-01T00:00:00Z", "+00:00", args("MAY", 2022, "JUN", 2022, "GMT"), true),
                of("2022-05-31T23:59:59Z", "+00:00", args("APR", 2022, "MAY", 2022, "GMT"), true),
                of("2022-04-30T23:59:59Z", "+00:00", args("MAY", 2022, "JUN", 2022, "GMT"), false),
                of("2022-06-01T00:00:00Z", "+00:00", args("APR", 2022, "MAY", 2022, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("APR", 2022, "APR", 2022, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("JUN", 2022, "JUN", 2022, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("MAY", 2021, "MAY", 2021, "GMT"), false),

                // 6 arguments: day1/month1/year1 and day2/month2/year2
                of("2022-05-23T12:34:56Z", "+02:00", args(23, "MAY", 2022, 23, "MAY", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(23, "MAY", 2022, 24, "MAY", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(22, "MAY", 2022, 23, "MAY", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(23, "MAY", 2022, 23, "MAY", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, "MAY", 2022, 31, "MAY", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, "APR", 2022, 30, "JUN", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, "JAN", 2022, 31, "DEC", 2022), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, "JAN", 2020, 31, "DEC", 2023), true),
                of("2022-05-22T22:00:00Z", "+02:00", args(23, "MAY", 2022, 23, "MAY", 2022), true),
                of("2022-05-23T21:59:59Z", "+02:00", args(23, "MAY", 2022, 23, "MAY", 2022), true),
                of("2022-05-22T21:59:59Z", "+02:00", args(23, "MAY", 2022, 23, "MAY", 2022), false),
                of("2022-05-23T22:00:00Z", "+02:00", args(23, "MAY", 2022, 23, "MAY", 2022), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, "JAN", 2020, 31, "DEC", 2021), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(22, "MAY", 2022, 22, "MAY", 2022), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(23, "APR", 2022, 23, "APR", 2022), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(23, "MAY", 2022, 23, "MAY", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(23, "MAY", 2022, 24, "MAY", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(22, "MAY", 2022, 23, "MAY", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(23, "MAY", 2022, 23, "MAY", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "MAY", 2022, 31, "MAY", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "APR", 2022, 30, "JUN", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "JAN", 2022, 31, "DEC", 2022, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "JAN", 2020, 31, "DEC", 2023, "GMT"), true),
                of("2022-05-23T00:00:00Z", "+00:00", args(23, "MAY", 2022, 23, "MAY", 2022, "GMT"), true),
                of("2022-05-23T23:59:59Z", "+00:00", args(23, "MAY", 2022, 23, "MAY", 2022, "GMT"), true),
                of("2022-05-22T23:59:59Z", "+00:00", args(23, "MAY", 2022, 23, "MAY", 2022, "GMT"), false),
                of("2022-05-24T00:00:00Z", "+00:00", args(23, "MAY", 2022, 23, "MAY", 2022, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "JAN", 2020, 31, "DEC", 2021, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(22, "MAY", 2022, 22, "MAY", 2022, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(23, "APR", 2022, 23, "APR", 2022, "GMT"), false),

                // too many parameters
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "MAY", 2000, 4, "OCT", 2022, 2022), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(1, "MAY", 2000, 4, "OCT", 2022, 2022, "GMT"), false)
                );
    }

    @ParameterizedTest
    @MethodSource
    void weekdayRange(String currentDateTime, String offset, Object[] args, boolean expectedResult) {

        // set clock to a fixed value in order to have consistent test results regardless of actual date/time/timezone
        setClock(currentDateTime, offset);

        assertThat(PacHelperFunctions.weekdayRange(args)).isEqualTo(expectedResult);
    }

    private static Stream<Arguments> weekdayRange() {
        return Stream.of(
                // first some error cases
                of("2022-05-23T12:34:56Z", "+02:00", new Object[0], false),
                of("2022-05-23T12:34:56Z", "+02:00", args("GMT"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("garbage"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("MON", "garbage"), false),

                // 1 weekday parameter
                of("2022-05-23T12:34:56Z", "+02:00", args("MON"), true),
                of("2022-05-24T12:34:56Z", "+02:00", args("TUE"), true),
                of("2022-05-25T12:34:56Z", "+02:00", args("WED"), true),
                of("2022-05-26T12:34:56Z", "+02:00", args("THU"), true),
                of("2022-05-27T12:34:56Z", "+02:00", args("FRI"), true),
                of("2022-05-28T12:34:56Z", "+02:00", args("SAT"), true),
                of("2022-05-29T12:34:56Z", "+02:00", args("SUN"), true),
                of("2022-05-22T12:34:56Z", "+02:00", args("SUN"), true),
                of("2022-05-22T22:00:00Z", "+02:00", args("MON"), true),
                of("2022-05-23T21:59:59Z", "+02:00", args("MON"), true),
                of("2022-05-22T21:59:59Z", "+02:00", args("MON"), false),
                of("2022-05-23T22:00:00Z", "+02:00", args("MON"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("MON", "GMT"), true),
                of("2022-05-24T12:34:56Z", "+00:00", args("TUE", "GMT"), true),
                of("2022-05-25T12:34:56Z", "+00:00", args("WED", "GMT"), true),
                of("2022-05-26T12:34:56Z", "+00:00", args("THU", "GMT"), true),
                of("2022-05-27T12:34:56Z", "+00:00", args("FRI", "GMT"), true),
                of("2022-05-28T12:34:56Z", "+00:00", args("SAT", "GMT"), true),
                of("2022-05-29T12:34:56Z", "+00:00", args("SUN", "GMT"), true),
                of("2022-05-22T12:34:56Z", "+00:00", args("SUN", "GMT"), true),
                of("2022-05-23T00:00:00Z", "+00:00", args("MON", "GMT"), true),
                of("2022-05-23T21:59:59Z", "+00:00", args("MON", "GMT"), true),
                of("2022-05-22T23:59:59Z", "+00:00", args("MON", "GMT"), false),
                of("2022-05-24T00:00:00Z", "+00:00", args("MON", "GMT"), false),

                // 2 weekday parameters
                of("2022-05-23T12:34:56Z", "+02:00", args("MON", "MON"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("SUN", "MON"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("MON", "TUE"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("SUN", "TUE"), true),
                of("2022-05-23T12:34:56Z", "+02:00", args("FRI", "WED"), true),
                of("2022-05-22T22:00:00Z", "+02:00", args("MON", "TUE"), true),
                of("2022-05-23T21:59:59Z", "+02:00", args("SUN", "MON"), true),
                of("2022-05-22T21:59:59Z", "+02:00", args("MON", "TUE"), false),
                of("2022-05-23T22:00:00Z", "+02:00", args("SUN", "MON"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("TUE", "WED"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("TUE", "SUN"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("MON", "MON", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("SUN", "MON", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("MON", "TUE", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("SUN", "TUE", "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args("FRI", "WED", "GMT"), true),
                of("2022-05-23T00:00:00Z", "+00:00", args("MON", "TUE", "GMT"), true),
                of("2022-05-23T21:59:59Z", "+00:00", args("SUN", "MON", "GMT"), true),
                of("2022-05-22T23:59:59Z", "+00:00", args("MON", "TUE", "GMT"), false),
                of("2022-05-24T00:00:00Z", "+00:00", args("SUN", "MON", "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("TUE", "WED", "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("TUE", "SUN", "GMT"), false),

                // too many parameters
                of("2022-05-23T12:34:56Z", "+02:00", args("MON", "TUE", "WED"), false),
                of("2022-05-23T12:34:56Z", "+02:00", args("MON", "TUE", "WED", "GMT"), false)
        );
    }

    @ParameterizedTest
    @MethodSource
    void timeRange(String currentDateTime, String offset, Object[] args, boolean expectedResult) {

        // set clock to a fixed value in order to have consistent test results regardless of actual date/time/timezone
        setClock(currentDateTime, offset);

        assertThat(PacHelperFunctions.timeRange(args)).isEqualTo(expectedResult);
    }

    private static Stream<Arguments> timeRange() {
        return Stream.of(
                // first some error cases
                of("2022-05-23T12:34:56Z", "+02:00", new Object[0], false),
                of("2022-05-23T12:34:56Z", "+00:00", args("GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("garbage"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args("garbage", "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(1234), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, "x", 14, 34), false),

                // 1 parameter (hour)
                of("2022-05-23T12:34:56Z", "+02:00", args(14), true),
                of("2022-05-23T12:00:00Z", "+02:00", args(14), true),
                of("2022-05-23T12:59:59Z", "+02:00", args(14), true),
                of("2022-05-23T13:00:00Z", "+02:00", args(15), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(13), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(24), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, "GMT"), true),
                of("2022-05-23T12:00:00Z", "+00:00", args(12, "GMT"), true),
                of("2022-05-23T12:59:59Z", "+00:00", args(12, "GMT"), true),
                of("2022-05-23T13:00:00Z", "+00:00", args(13, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(13, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(24, "GMT"), false),

                // 2 parameters (hour1/2)
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 14), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 15), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(13, 14), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(13, 15), true),
                of("2022-05-23T01:34:56Z", "+02:00", args(20, 10), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(20, 10), false),
                of("2022-05-23T12:00:00Z", "+02:00", args(14, 15), true),
                of("2022-05-23T12:59:59Z", "+02:00", args(13, 14), true),
                of("2022-05-23T11:59:59Z", "+02:00", args(14, 15), false),
                of("2022-05-23T13:00:00Z", "+02:00", args(13, 14), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(15, 18), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 12, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 13, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 13, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(11, 14, "GMT"), true),
                of("2022-05-23T12:00:00Z", "+00:00", args(12, 13, "GMT"), true),
                of("2022-05-23T12:59:59Z", "+00:00", args(11, 12, "GMT"), true),
                of("2022-05-23T11:59:59Z", "+00:00", args(12, 13, "GMT"), false),
                of("2022-05-23T13:00:00Z", "+00:00", args(11, 12, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(14, 18, "GMT"), false),

                // 4 parameters (hour1/minutes1 and hour2/minutes2)
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 14, 34), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 33, 14, 34), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 14, 35), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(13, 34, 14, 34), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 15, 34), true),
                of("2022-05-23T12:34:00Z", "+02:00", args(14, 34, 14, 34), true),
                of("2022-05-23T12:34:59Z", "+02:00", args(14, 34, 14, 34), true),
                of("2022-05-23T12:33:59Z", "+02:00", args(14, 34, 14, 34), false),
                of("2022-05-23T12:35:00Z", "+02:00", args(14, 34, 14, 34), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 12, 34, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 33, 12, 34, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 12, 35, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(11, 34, 12, 34, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 13, 34, "GMT"), true),
                of("2022-05-23T12:34:00Z", "+00:00", args(12, 34, 12, 34, "GMT"), true),
                of("2022-05-23T12:34:59Z", "+00:00", args(12, 34, 12, 34, "GMT"), true),
                of("2022-05-23T12:33:59Z", "+00:00", args(12, 34, 12, 34, "GMT"), false),
                of("2022-05-23T12:35:00Z", "+00:00", args(12, 34, 12, 34, "GMT"), false),

                // 6 parameters (hour1/minutes1/seconds1 and hour2/minutes2/seconds2)
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 56, 14, 34, 56), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 55, 14, 34, 56), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 56, 14, 34, 57), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(13, 34, 56, 14, 34, 56), true),
                of("2022-05-23T22:00:00Z", "+02:00", args(0, 0, 0, 0, 0, 30), true),
                of("2022-05-23T22:00:30Z", "+02:00", args(0, 0, 0, 0, 0, 30), true),
                of("2022-05-23T22:00:31Z", "+02:00", args(0, 0, 0, 0, 0, 30), false),
                of("2022-05-23T21:59:59Z", "+02:00", args(0, 0, 0, 0, 0, 30), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 56, 14, 35, 0), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 0, 14, 34, 56), true),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 57, 14, 35, 0), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(14, 34, 0, 14, 34, 55), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(13, 34, 56, 13, 34, 56), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 56, 12, 34, 56, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 55, 12, 34, 56, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 56, 12, 34, 57, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(11, 34, 56, 12, 34, 56, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 56, 12, 35, 0, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 0, 12, 34, 56, "GMT"), true),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 57, 12, 35, 0, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 34, 0, 12, 34, 55, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(13, 34, 56, 13, 34, 56, "GMT"), false),
                of("2022-05-23T12:34:56Z", "+00:00", args(12, 12, 12, 12, 12, 12, "GMT"), false),

                // too many parameters
                of("2022-05-23T12:34:56Z", "+02:00", args(1, 2, 3, 4, 5, 6, 7), false),
                of("2022-05-23T12:34:56Z", "+02:00", args(1, 2, 3, 4, 5, 6, 7, "GMT"), false)
        );
    }

    private void setClock(String currentDateTime, String offset) {
        PacHelperFunctions.setClock(Clock.fixed(Instant.parse(currentDateTime), ZoneOffset.of(offset)));
    }

    private static Object[] args(Object... args) {
        return args;
    }
}