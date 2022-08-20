package org.kse.utilities.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.TemporalAdjusters;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.kse.utilities.StringUtils;

/**
 * Implementation of the 12 PAC script helper functions as defined by Netscape.
 * <p>
 * As those functions were defined at a time when IPv6 was not existent, they work with IPv4 addresses only.
 * </p>
 */
public class PacHelperFunctions {

    static final Pattern IP_ADDR_PATTERN = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");

    static final List<String> WEEKDAYS = Arrays.asList("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN");

    static final List<String> MONTHS = Arrays.asList("JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP",
            "OCT", "NOV", "DEC");

    private PacHelperFunctions() {
        // hide default c-tor
    }

    // explicitly define a clock for overriding the current time in unit tests
    private static Clock clock = Clock.systemDefaultZone();
    static void setClock(Clock newClock) {
        clock = newClock;
    }

    /**
     * In browsers the message of alert() is logged to the console, so we do something similar
     * @param message The message
     */
    public static void alert(String message) {
        System.out.println(message);
    }

    /**
     * Returns true if the domain of hostname matches.
     *
     * @param host   Hostname from URL
     * @param domain The domain to test the hostname against
     * @return True, if host matches domain
     */
    public static boolean dnsDomainIs(String host, String domain) {
        if (StringUtils.isBlank(host) || StringUtils.isBlank(domain)) {
            return false;
        }
        return host.endsWith(domain);
    }

    /**
     * Returns the number of DNS domain levels (number of dots) in the hostname.
     *
     * @param host Hostname (e.g. www.example.com)
     * @return Number of domain levels
     */
    public static int dnsDomainLevels(String host) {
        if (StringUtils.isBlank(host)) {
            return 0;
        }
        return host.split("\\.").length - 1;
    }

    /**
     * Resolves the given DNS hostname into an IPv4 address, and returns it in the dot separated format as a string.
     *
     * @param host A host name
     * @return The resolved IPv4 address for the given hostname or an empty string if an error has occurred
     */
    public static String dnsResolve(String host) {
        if (StringUtils.isBlank(host)) {
            return "";
        }
        try {
            return InetAddress.getByName(host).getHostAddress();
        } catch (UnknownHostException e) {
            return "";
        }
    }

    /**
     * Returns the IPv4 address of the host that the application is running on,
     * as a string in the dot-separated integer format.
     *
     * @return IPv4 address of local machine or an empty string if an error has occurred
     */
    public static String myIpAddress() {
        return IpAddress.getIpAddress();
    }

    /**
     * True if the IP address of the host matches the specified IP address pattern.
     *
     * @param ipAddr  An IPv4 address
     * @param pattern A network pattern
     * @param mask    A net mask
     * @return True, if IP address matches pattern/mask
     */
    public static boolean isInNet(String ipAddr, String pattern, String mask) {

        byte[] ipAddrBytes = convertIpv4AddressToBytes((ipAddr));
        byte[] patternBytes = convertIpv4AddressToBytes((pattern));
        byte[] maskBytes = convertIpv4AddressToBytes((mask));

        if (ipAddrBytes == null || patternBytes == null || maskBytes == null) {
            return false;
        }

        return ((ipAddrBytes[0] & maskBytes[0]) == (patternBytes[0] & maskBytes[0])) &&
               ((ipAddrBytes[1] & maskBytes[1]) == (patternBytes[1] & maskBytes[1])) &&
               ((ipAddrBytes[2] & maskBytes[2]) == (patternBytes[2] & maskBytes[2])) &&
               ((ipAddrBytes[3] & maskBytes[3]) == (patternBytes[3] & maskBytes[3]));
    }

    /**
     * True if there is no domain name in the hostname (no dots).
     *
     * @param host A hostname
     * @return True, if no dots in hostname
     */
    public static boolean isPlainHostName(String host) {
        return dnsDomainLevels(host) == 0;
    }

    /**
     * Tries to resolve the hostname.
     *
     * @return True if resolving hostname succeeds
     */
    public static boolean isResolvable(String host) {
        return !StringUtils.isBlank(dnsResolve(host));
    }

    /**
     * Is true if the hostname matches exactly the specified domain,
     * or if there is no domain name part in the hostname, but the unqualified hostname matches.
     *
     * @param hostname A hostname
     * @param domain A fully qualified hostname to match against
     * @return True, if hostname matches the domain
     */
    public static boolean localHostOrDomainIs(String hostname, String domain) {
        if (StringUtils.isBlank(hostname) || StringUtils.isBlank(domain)) {
            return false;
        }
        return (Objects.equals(hostname, domain)) || (!hostname.contains(".") && domain.startsWith(hostname));
    }

    /**
     * Returns true if the string matches the specified shell (not regex!) expression.
     *
     * @param url     A hostname or URL
     * @param pattern Matching pattern with shell-style wildcards ("globs")
     * @return True, if url matches the pattern
     */
    public static boolean shExpMatch(String url, String pattern) {
        StringBuilder sb = new StringBuilder("^");
        for (int i = 0; i < pattern.length(); ++i) {
            switch (pattern.charAt(i)) {
            case '.':
                sb.append("\\.");
                break;
            case '*':
                sb.append(".*");
                break;
            case '?':
                sb.append('.');
                break;
            default:
                sb.append(pattern.charAt(i));
            }
        }
        String regex = sb.append('$').toString();

        if (url == null) {
            return "".matches(regex);
        }

        return url.matches(regex);
    }

    /**
     * Tests if current date is within a date range.
     * <p>
     * There are several forms of this method from JavaScript:
     * <p>
     * dateRange(day)
     * dateRange(day1, day2)
     * dateRange(mon)
     * dateRange(month1, month2)
     * dateRange(year)
     * dateRange(year1, year2)
     * dateRange(day1, month1, day2, month2)
     * dateRange(month1, year1, month2, year2)
     * dateRange(day1, month1, year1, day2, month2, year2)
     * dateRange(day1, month1, year1, day2, month2, year2, gmt)
     * <p>
     * Even if not shown above, the gmt parameter can always be added as an (optional) last parameter.
     * <p>
     * -  day is the day of month between 1 and 31 (as an integer).
     * -  month is one of the month strings: JAN FEB MAR APR MAY JUN JUL AUG SEP OCT NOV DEC
     * -  year is the full year number with 4 digits, for example 1995. (as an integer)
     * -  gmt is either the string "GMT", which makes time comparison occur in GMT timezone; or if not present,
     * times are taken to be in the local timezone. If this parameter exists it must always be the last parameter.
     *
     * @param args One or two dates as specified above and an optional GMT flag
     * @return True, if current date is within the given date range
     */
    public static boolean dateRange(Object... args) {
        if (args.length == 0) {
            return false;
        }

        boolean isGMT = "GMT".equals(args[args.length - 1]);
        int argCount = isGMT ? args.length - 1 : args.length;
        ZoneId zoneId = getZoneId(isGMT);
        ZonedDateTime now = getCurrentZonedDateTime(zoneId);

        // invalid number of parameters
        if (argCount == 0 || argCount > 6) {
            return false;
        }

        // special case "only one argument": just check if day, month and year match
        if (argCount == 1) {
            ZonedDateTime otherZdt = updateZonedDateTimeWithValueFromParams(now, args[0]);

            return now.getDayOfMonth() == otherZdt.getDayOfMonth() &&
                   now.getMonth().equals(otherZdt.getMonth()) &&
                   now.getYear() == otherZdt.getYear();
        }

        // init dates that are used for comparison later with default values
        ZonedDateTime date1 = getCurrentZonedDateTime(zoneId).with(TemporalAdjusters.firstDayOfYear())
                                                             .withHour(0)
                                                             .withMinute(0).withSecond(0);
        ZonedDateTime date2 = getCurrentZonedDateTime(zoneId).with(TemporalAdjusters.lastDayOfYear())
                                                             .withHour(23)
                                                             .withMinute(59).withSecond(59);

        // first half of arguments always belongs to first date
        for (int i = 0; i < argCount / 2; i++) {
            date1 = updateZonedDateTimeWithValueFromParams(date1, args[i]);
        }

        // now same for second date / second half of arguments
        for (int i = argCount / 2; i < argCount; i++) {
            date2 = updateZonedDateTimeWithValueFromParams(date2, args[i]);
        }

        // if only day is given, adjust months to current month
        if ((argCount <= 2) && (args[0] instanceof Number) && (((Number) args[0]).intValue() <= 31)) {
            date1 = date1.withMonth(now.getMonth().getValue());
            date2 = date2.withMonth(now.getMonth().getValue());
        }

        // convert to long values because isAfter()/isBefore() are not inclusive
        return date1.toInstant().toEpochMilli() <= now.toInstant().toEpochMilli()
               && now.toInstant().toEpochMilli() <= date2.toInstant().toEpochMilli();
    }

    /**
     * Tests if current day is within a day-of-week range.
     *
     * There are several forms of this method from JavaScript:
     *
     *     weekdayRange(wd1)
     *     weekdayRange(wd1, gmt)
     *     weekdayRange(wd1, wd2)
     *     weekdayRange(wd1, wd2, gmt)
     *
     * Parameters:
     *   -  wd1 and wd2 are weekday specifications.
     *   -  gmt is either the string "GMT", which makes time comparison occur in GMT timezone; or if not present,
     *      times are taken to be in the local timezone. If this parameter exists it must always be the last parameter.
     *
     * If only wd1 is present, the function yields a true value on the weekday that the parameter represents.
     * If both wd1 and wd2 are specified, the condition is true if the current weekday is in between those two weekdays.
     * Bounds are inclusive.
     *
     * The weekday abbreviations used in wd1 and wd2 must be one of the following:
     *
     *     MON  TUE  WED  THU  FRI  SAT  SUN
     *
     * @param args See spec above
     * @return True, if current weekday is in the given range
     */
    public static boolean weekdayRange(Object... args) {
        if (args.length == 0) {
            return false;
        }

        boolean isGMT = "GMT".equals(args[args.length - 1]);
        int argCount = isGMT ? args.length - 1 : args.length;
        ZoneId zoneId = getZoneId(isGMT);
        ZonedDateTime now = getCurrentZonedDateTime(zoneId);

        // single weekday parameter
        if (argCount == 1) {
            if (WEEKDAYS.contains(args[0])) {
                String currentWeekday = WEEKDAYS.get(now.getDayOfWeek().getValue() - 1);
                return currentWeekday.equals(args[0]);
            }
            return false;
        }

        // two weekday parameters
        if (argCount == 2) {
            int wd1Index = WEEKDAYS.indexOf(args[0]);
            int wd2Index = WEEKDAYS.indexOf(args[1]);

            if (wd1Index == -1 || wd2Index == -1) {
                return false;
            }

            int currentDayIndex = now.getDayOfWeek().getValue() - 1;

            // something like weekdayRange("WED", "TUE") is allowed
            if (wd2Index < wd1Index) {
                return wd1Index <= currentDayIndex || currentDayIndex <= wd2Index;
            }

            return wd1Index <= currentDayIndex && currentDayIndex <= wd2Index;
        }

        return false;
    }

    /**
     * Tests if current time is within a time range.
     *
     * There are several forms of this method from JavaScript:
     *    timeRange(hour)
     *    timeRange(hour1, hour2)
     *    timeRange(hour1, min1, hour2, min2)
     *    timeRange(hour1, min1, sec1, hour2, min2, sec2)
     *    timeRange(hour1, min1, sec1, hour2, min2, sec2, gmt)
     *
     * Even if not shown above, the gmt parameter can always be added as an (optional) last parameter.
     *
     *    - hour is the hour from 0 to 23. (0 is midnight, 23 is 11 pm.)
     *    - min minutes from 0 to 59.
     *    - sec seconds from 0 to 59.
     *    - gmt is either the string "GMT", which makes time comparison occur in GMT timezone; or if not present,
     *      times are taken to be in the local timezone. If this parameter exists it must always be the last parameter.
     *
     * @param args See spec above
     * @return True, if current time is within the given range
     */
    public static boolean timeRange(Object... args) {
        if (args.length == 0) {
            return false;
        }

        boolean isGMT = "GMT".equals(args[args.length - 1]);
        int argCount = isGMT ? args.length - 1 : args.length;
        ZoneId zoneId = getZoneId(isGMT);
        ZonedDateTime now = getCurrentZonedDateTime(zoneId);

        // only parameter is "GMT"
        if (argCount == 0) {
            return false;
        }

        // only one hour parameter
        if (argCount == 1) {
            if (args[0] instanceof Number) {
                return now.getHour() == getTime((Number) args[0]);
            }
            return false;
        }

        // init dates that are used later for comparison with default values
        ZonedDateTime date1 = getCurrentZonedDateTime(zoneId).withHour(0).withMinute(0).withSecond(0);
        ZonedDateTime date2 = getCurrentZonedDateTime(zoneId).withHour(23).withMinute(59).withSecond(59);

        if (areNotInstanceOfNumber(args, argCount)) {
            return false;
        }

        switch (argCount) {
        case 6:
            date1 = date1.withHour(getTime((Number) args[0]))
                         .withMinute(getTime((Number) args[1]))
                         .withSecond(getTime((Number) args[2]));
            date2 = date2.withHour(getTime((Number) args[3]))
                         .withMinute(getTime((Number) args[4]))
                         .withSecond(getTime((Number) args[5]));
            break;
        case 4:
            date1 = date1.withHour(getTime((Number) args[0])).withMinute(getTime((Number) args[1]));
            date2 = date2.withHour(getTime((Number) args[2])).withMinute(getTime((Number) args[3]));
            break;
        case 2:
            date1 = date1.withHour(getTime((Number) args[0]));
            date2 = date2.withHour(getTime((Number) args[1]));
            break;
        default:
            // wrong number of arguments
            return false;
        }

        // handle special case where the given time range crosses midnight
        if (date2.isBefore(date1)) {
            return now.toInstant().toEpochMilli() <= date2.toInstant().toEpochMilli()
                   || now.toInstant().toEpochMilli() >= date1.toInstant().toEpochMilli();
        }

        // convert to long values because isAfter()/isBefore() are not inclusive
        return date1.toInstant().toEpochMilli() <= now.toInstant().toEpochMilli()
               && now.toInstant().toEpochMilli() <= date2.toInstant().toEpochMilli();
    }

    private static boolean areNotInstanceOfNumber(Object[] args, int argsToCheck) {
        for (int i = 0; i < argsToCheck; i++) {
            if (!(args[i] instanceof Number)) {
                return true;
            }
        }
        return false;
    }

    private static int getTime(Number arg) {
        return arg.intValue();
    }

    private static ZonedDateTime updateZonedDateTimeWithValueFromParams(ZonedDateTime zdt, Object value) {
        if (MONTHS.contains(value)) {
            return zdt.withMonth(MONTHS.indexOf(value) + 1);
        } else if (value instanceof Number) {
            int intValue = ((Number) value).intValue();
            if (intValue <= 31) {
                return zdt.withDayOfMonth(intValue);
            } else {
                return zdt.withYear(intValue);
            }
        } else {
            // "GMT" or garbage
            return zdt;
        }
    }

    private static byte[] convertIpv4AddressToBytes(String ipAddr) {
        Matcher matcher = IP_ADDR_PATTERN.matcher(ipAddr);
        if (!matcher.matches()) {
            return null;
        }

        byte[] result = new byte[4];
        try {
            for (int i = 1; i <= 4; i++) {
                int group = Integer.parseInt(matcher.group(i));
                if (group < 0 || group > 255) {
                    return null;
                }
                result[i - 1] = (byte) group;
            }
        } catch (Exception e) {
            return null;
        }

        return result;
    }

    private static ZoneId getZoneId(boolean isGMT) {
        return isGMT ? ZoneOffset.UTC : clock.getZone();
    }

    private static ZonedDateTime getCurrentZonedDateTime(ZoneId zoneId) {
        return ZonedDateTime.now(clock.withZone(zoneId));
    }
}